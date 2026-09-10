// SPDX-License-Identifier: AGPL-3.0-or-later

//! `PplnsEngine` — top-level wiring of the PPLNS service-engine.
//!
//! Owns the Postgres pool, the Redis-backed `WindowStore`, the
//! `DistributionBuilder` (with its inflight cache), the touch-buffer
//! flush background task, and the daily 03:00-UTC dust-sweep background
//! task.
//!
//! Construction:
//!
//! ```no_run
//! # use bp_pplns_engine::{config::PplnsEngineConfig, engine::PplnsEngine};
//! # use bp_pplns_engine::window::NetworkDifficulty;
//! # async fn wire(
//! #     config: PplnsEngineConfig,
//! #     redis: redis::aio::ConnectionManager,
//! #     pg: sqlx::PgPool,
//! #     net_diff: NetworkDifficulty,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let engine = PplnsEngine::spawn(config, redis, pg, net_diff).await?;
//! # let _ = engine;
//! # Ok(()) }
//! ```
//!
//! Public API:
//!
//! - [`PplnsEngine::record_share`] — hot path; called per accepted share
//!   *after* the stratum layer has resolved mode = PPLNS and consumed
//!   any per-session warmup quota.
//! - [`PplnsEngine::build_distribution`] — called by the
//!   template-build path (and the JDP coinbase-outputs request path),
//!   wraps the inflight cache.
//! - [`PplnsEngine::on_block_found`] — called when a PPLNS-mode finder
//!   wins a block; reads the snapshot persisted at template-build
//!   time, applies the ledger TX, then deletes the snapshot.
//! - [`PplnsEngine::shutdown`] — flips the cancel watch so background
//!   tasks exit cleanly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bp_common::{AddressId, InvalidAddressError, Sats};
use bp_db::{DbError, PplnsBalanceRow};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::{ConfigError, PplnsEngineConfig};
use crate::distribution::{
    DistributionBuilder, DistributionConfig, DistributionError, DistributionResult,
};
use crate::ledger::touch_buffer::{spawn_flush_task, TouchBuffer};
use crate::ledger::{
    apply_distribution, pending_row, ApplyDistributionResult, AuditRow, BalanceWrite, LedgerError,
    PayoutRowType,
};
use crate::sweep::{spawn_daily_task, DustSweepRunner, SweepError, SystemClock};
use crate::window::{snapshot::StoredWeightSnapshot, NetworkDifficulty, WindowError, WindowStore};
use bp_coinbase_snapshot::{
    ActualCoinbase, InstalledResolver, PaidAtHeight, PaidAtHeightError, PayoutIdentityResolver,
};
use bp_share::{block_subsidy_sats, claim_sats};

/// Errors surfaced across the engine boundary.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("window: {0}")]
    Window(#[from] WindowError),
    #[error("db: {0}")]
    Db(#[from] DbError),
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("sweep: {0}")]
    Sweep(#[from] SweepError),
    #[error("distribution: {0}")]
    Distribution(Arc<DistributionError>),
    #[error("snapshot missing for block {block_height} — pool restart or expired TTL?")]
    SnapshotMissing { block_height: i32 },
    #[error(
        "no snapshot under the winning job's payout list — the block needs an \
         operator reprocess from its own coinbase"
    )]
    SnapshotMissingForPayouts,
    #[error(
        "block {block_height} carried no payout fingerprint — the pool did not \
         build this coinbase (JD-client custom job), so there is no pool-side \
         distribution to book"
    )]
    NoPayoutFingerprint { block_height: i32 },
    #[error(
        "block {block_height} coinbase pays {actual_reward} sats, less than the \
         {subsidy} sat subsidy the block was entitled to — it forfeited money, so \
         nothing about it is trustworthy enough to book unattended"
    )]
    RevenueBelowSubsidy {
        block_height: i32,
        actual_reward: u64,
        subsidy: u64,
    },
    #[error("on_block_found already in flight — concurrent block-find for same engine")]
    BlockFoundInProgress,
    #[error("invalid address in snapshot: {0}")]
    Address(#[from] InvalidAddressError),
    #[error("payment attribution: {0}")]
    PaymentAttribution(#[from] PaidAtHeightError),
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
            | EngineError::SnapshotMissingForPayouts
            | EngineError::NoPayoutFingerprint { .. }
            | EngineError::RevenueBelowSubsidy { .. }
            | EngineError::Address(_) => true,
            // A ledger error is usually infrastructure, but one of them is a
            // verdict: a height that already carries a different block's
            // payout rows will still carry them next tick. `LedgerError`
            // owns that distinction so this engine and Group-Solo cannot
            // disagree about it.
            EngineError::Ledger(e) => e.is_terminal(),
            // Same shape, same reason: the attribution errors own their own
            // classification so PPLNS and Group-Solo cannot disagree about
            // which of them is a verdict.
            EngineError::PaymentAttribution(e) => e.is_terminal(),
            // Infrastructure, and the in-flight guard — all of these
            // clear on their own.
            EngineError::Redis(_)
            | EngineError::Window(_)
            | EngineError::Db(_)
            | EngineError::Sweep(_)
            | EngineError::Distribution(_)
            | EngineError::BlockFoundInProgress => false,
        }
    }
}

/// Top-level handle. Cloneable (`Arc<Inner>`); callers share one
/// engine across the whole pool.
#[derive(Clone)]
pub struct PplnsEngine {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    window: WindowStore,
    distribution_builder: DistributionBuilder,
    touch_buffer: Arc<TouchBuffer>,
    config: PplnsEngineConfig,
    cancel_tx: watch::Sender<bool>,
    block_found_in_progress: AtomicBool,
    /// Who is behind a ledger key — read twice per block, from the two ends of
    /// the split, through **one** handle.
    ///
    /// The distribution builder above holds a clone of this same
    /// [`InstalledResolver`] and asks it which keys are rotating before it filters
    /// them into the coinbase; settlement asks it which address each key was paid
    /// under ~100 blocks later. Sharing the handle rather than the rule is
    /// load-bearing: a row paid by a resolver that knows it and then booked by one
    /// that does not is the double credit
    /// [`PaidAtHeightError::Unresolvable`] exists to refuse.
    ///
    /// Unset means [`bp_coinbase_snapshot::StaticPaidAddresses`] — correct for a pool with no rotating
    /// identities, and a refusal for any key that is not a payable address, so
    /// leaving it unset can never misbook a `payout_id`. `bin/blitzpool` installs
    /// the descriptor-aware one at startup
    /// ([`PplnsEngine::install_payout_identity_resolver`]).
    ///
    /// Installed rather than passed to the constructor because `Inner` lives
    /// behind an `Arc` shared by every clone of the handle, and because the
    /// resolver needs the identity directory, which is built after the engines.
    identity_resolver: InstalledResolver,
}

impl PplnsEngine {
    /// Validate config, wire dependencies, spawn the two background
    /// tasks (touch-buffer flush + daily dust-sweep), return a handle.
    ///
    /// The caller owns the `ConnectionManager` lifecycle indirectly:
    /// the engine clones it into the `WindowStore`; on `shutdown` the
    /// background tasks exit and the engine's last `Arc` drop closes
    /// the connection.
    pub async fn spawn(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, net_diff, true).await
    }

    /// Core-mode constructor: same wiring, but *without* the background
    /// crons (touch-buffer flush + dust-sweep). The Core only reads the
    /// window and builds distributions (`build_distribution`, which still
    /// writes the snapshot key); all ledger-mutating crons run on the
    /// Satellite. `record_share` is unaffected and unused on the Core
    /// (the share path produces to the stream instead).
    pub async fn spawn_core(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, net_diff, false).await
    }

    async fn spawn_inner(
        config: PplnsEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
        net_diff: NetworkDifficulty,
        background_tasks: bool,
    ) -> Result<Self, EngineError> {
        let config = config.try_new()?;
        let window = WindowStore::new(
            redis,
            config.window_factor,
            config.bucket_shares,
            net_diff,
            config.abandoned_balance_days,
        );
        // Cold-start safety: if the by-address aggregate is empty but buckets
        // exist (fresh deploy / lost key), rebuild it once from the buckets.
        // No-op at a normal cutover, where the previous pool version already
        // maintains the hash. After this the hash
        // is kept current incrementally; there is no periodic full recalc.
        window.bootstrap_window_if_needed().await?;
        // Convert a bucket index written before the scores were timestamps.
        // Must run before the first trim, or the age rule reads ids as 1970
        // and drops the whole window. Idempotent, so it stays as a permanent
        // guard rather than a one-release migration.
        //
        // Deliberately NOT gated on `background_tasks`, so it runs in every
        // role, Core included. The trim runs wherever the share stream is
        // consumed, and that is a role question this constructor does not
        // see: `background_tasks` is the Payout role alone, while a Stats
        // satellite without Front consumes the stream too. A gate here could
        // leave exactly the trimming process unconverted. The cost of running
        // it everywhere is one empty ZRANGEBYSCORE per boot.
        window.restamp_legacy_bucket_scores().await?;
        let dist_cfg = DistributionConfig::from_engine_config(&config);
        // One handle, two readers — the builder's job-path filter and this
        // engine's settlement. See `Inner::identity_resolver`.
        let identity_resolver = InstalledResolver::default();
        let distribution_builder = DistributionBuilder::new(pool.clone(), window.clone(), dist_cfg)
            .with_identities(identity_resolver.clone());
        let touch_buffer = Arc::new(TouchBuffer::new());
        let clock = Arc::new(SystemClock);
        let sweep_runner = DustSweepRunner::new(pool.clone(), clock, config.abandoned_balance_days);

        let (cancel_tx, cancel_rx) = watch::channel(false);

        // Spawn background tasks. We don't track JoinHandles in the
        // engine because shutdown is signalled by `cancel_tx` and the
        // tasks self-terminate. If callers need precise join semantics
        // they should wrap the engine in their own supervisor.
        //
        // Core mode (`background_tasks == false`) skips them entirely:
        // touch-flush + dust-sweep write the ledger, which is the
        // Satellite's job. The cancel channel is still wired so
        // `shutdown` stays a no-op-safe call in either mode.
        if background_tasks {
            std::mem::drop(spawn_flush_task(
                pool.clone(),
                touch_buffer.clone(),
                Duration::from_secs(config.touch_flush_interval_secs as u64),
                cancel_rx.clone(),
            ));
            std::mem::drop(spawn_daily_task(
                sweep_runner.clone(),
                config.dust_sweep_enabled,
                cancel_rx,
            ));
        }

        info!(
            window_factor = config.window_factor,
            min_payout_sats = config.min_payout_sats.0,
            fee_percent = config.fee_percent,
            dust_sweep_enabled = config.dust_sweep_enabled,
            // One field, not two: the window's age rule reads the same knob.
            abandoned_balance_days = config.abandoned_balance_days,
            background_tasks,
            "pplns-engine spawned"
        );

        Ok(Self {
            inner: Arc::new(Inner {
                pool,
                window,
                distribution_builder,
                touch_buffer,
                config,
                cancel_tx,
                block_found_in_progress: AtomicBool::new(false),
                identity_resolver,
            }),
        })
    }

    /// Hot path. Called per accepted share AFTER the stratum layer has
    /// resolved mode = PPLNS and the per-session warmup is past.
    ///
    /// Atomically appends the share to the window (Redis MULTI/EXEC),
    /// records the `lastAcceptedShareAt` touch (60s-buffered to PG),
    /// and invalidates the distribution cache so the next
    /// `build_distribution` call sees the new share.
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        address: &str,
        difficulty: f64,
        timestamp_ms: u64,
    ) -> Result<(), EngineError> {
        let applied = self
            .inner
            .window
            .record_share(share_id, address, difficulty, timestamp_ms)
            .await?;
        if !applied {
            // Deduped redelivery: the window already counts this share, so
            // the touch + cache-invalidate would be redundant work (and a
            // redundant lastAcceptedShareAt bump). Skip them.
            return Ok(());
        }
        self.inner.touch_buffer.mark(address, timestamp_ms as i64);
        // The distribution depends on (window + ledger); a new share
        // changes the window. Invalidate so the next template-build
        // call sees fresh state. Invalidating per-reward would let
        // stale entries for *other* reward values survive — the whole
        // cache is keyed by reward, so dropping all entries is
        // correct (and cheap: one HashMap::clear).
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// The live coinbase-weight-budget handle. The autoscaler driver clones
    /// this to read pressure samples and write stepped values at runtime.
    pub fn coinbase_budget(&self) -> crate::autoscale::LiveBudget {
        self.inner.distribution_builder.live_budget()
    }

    /// Drop all cached distributions. The autoscaler driver calls this right
    /// after changing the live budget so the next build re-runs the trimmer
    /// against the new value instead of serving a stale cached result.
    pub fn invalidate_distribution_cache(&self) {
        self.inner.distribution_builder.invalidate_all();
    }

    /// Build the current PPLNS payout distribution for a given
    /// `block_reward_sats`. Wraps the inflight cache, persists a
    /// snapshot to Redis so `on_block_found` can replay deterministically.
    pub async fn build_distribution(
        &self,
        block_reward_sats: u64,
    ) -> Result<Arc<DistributionResult>, EngineError> {
        self.inner
            .distribution_builder
            .build(block_reward_sats)
            .await
            .map_err(EngineError::Distribution)
    }

    /// The empty-window answer for one asking miner — see
    /// [`crate::distribution::DistributionBuilder::build_bootstrap`].
    ///
    /// Only valid after [`Self::build_distribution`] answered
    /// [`bp_pplns::WeightBuildError::NoScoredMiners`]. The caller is the
    /// payout resolver, which is the only place that knows which miner is
    /// asking; the pool-wide JDP publisher must NOT use this — it builds
    /// one distribution for every job-declaring client at once and has
    /// nobody to name.
    pub async fn build_bootstrap_distribution(
        &self,
        block_reward_sats: u64,
        claimant: &AddressId,
    ) -> Result<Arc<DistributionResult>, EngineError> {
        self.inner
            .distribution_builder
            .build_bootstrap(block_reward_sats, claimant)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Look up the settlement inputs the found block's coinbase was built
    /// from, so the Core can stamp them into the block-found event.
    ///
    /// This exists for the same reason as Group-Solo's namesake, and it is
    /// resolved at the same moment: at the block-found instant, where the
    /// snapshot key is certainly still alive. The confirmation-gated apply
    /// runs `confirmation_depth` blocks later — about 20 minutes at depth 3,
    /// against a 20-minute [`crate::config::PplnsEngineConfig::snapshot_ttl_secs`]
    /// whose clock started when the winning JOB was built. Reading it only
    /// then loses the race about half the time, and losing it is not a
    /// delay: the inputs are gone from every store (the Redis→Postgres
    /// backup skips per-job snapshot keys on purpose), so what the
    /// withheld miners were owed can no longer be computed from anything.
    /// The block's own coinbase says who WAS paid, never what the unpaid
    /// were entitled to.
    ///
    /// `weights_fingerprint` is the identity of the winning job's payout
    /// list, carried on the job the share was built on. The build that
    /// produced that list stored its snapshot under it, and nothing else
    /// writes that key.
    pub async fn weight_snapshot_for_block_found(
        &self,
        weights_fingerprint: &[u8; 32],
    ) -> Result<StoredWeightSnapshot, EngineError> {
        let mut conn = self.inner.window.connection_for_snapshot();
        bp_coinbase_snapshot::resolve_snapshot_for_block_found(
            &mut conn,
            crate::window::snapshot_key_for,
            weights_fingerprint,
            "pplns",
        )
        .await?
        .ok_or(EngineError::SnapshotMissingForPayouts)
    }

    /// Install the descriptor-aware payout-identity resolver.
    /// Idempotent-by-refusal: returns `false` if one was already installed, and
    /// keeps the first.
    ///
    /// Only `bin/blitzpool` calls this, once, at startup — it is the only place
    /// that has the identity directory and the Postgres pool together. Until it
    /// does, settlement uses [`bp_coinbase_snapshot::StaticPaidAddresses`], which refuses any ledger key
    /// that is not a payable address rather than settling one wrongly.
    ///
    /// This also reaches the **distribution builder**, which shares the handle:
    /// installing here is what makes a rotating miner's row survive into the
    /// coinbase in the first place. There is nothing to install twice.
    pub fn install_payout_identity_resolver(
        &self,
        resolver: Arc<dyn PayoutIdentityResolver>,
    ) -> bool {
        self.inner.identity_resolver.install(resolver)
    }

    /// The installed resolver, or the static-only default.
    fn identity_resolver(&self) -> Arc<dyn PayoutIdentityResolver> {
        self.inner.identity_resolver.get()
    }

    /// Apply a found block: settle `claim(T_actual) − paid` per address
    /// against the block's OWN coinbase, then write the payout history.
    ///
    /// `snapshot` is the distribution's settlement inputs. The Core
    /// resolves them at found-time and both paths carry them in — the
    /// confirmation-gated one in the parked blob, the immediate one
    /// straight through. `None` is the fallback for the case where that
    /// resolution failed (a Redis blip at the worst moment): the
    /// fingerprint is then read back here, which is a second chance, not
    /// the design.
    ///
    /// Idempotent on redelivery without a guard of its own:
    /// `pplns_payout_history` is UNIQUE on `(blockHeight, address)` and
    /// the balance upsert only runs when history rows were actually
    /// inserted, so a second delivery writes nothing and reports
    /// `history_inserted == 0`.
    pub async fn on_block_found(
        &self,
        block_height: i32,
        actual: &ActualCoinbase,
        snapshot: Option<StoredWeightSnapshot>,
        payouts_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        if self
            .inner
            .block_found_in_progress
            .swap(true, Ordering::SeqCst)
        {
            return Err(EngineError::BlockFoundInProgress);
        }
        let result = self
            .on_block_found_inner(block_height, actual, snapshot, payouts_fingerprint)
            .await;
        self.inner
            .block_found_in_progress
            .store(false, Ordering::SeqCst);
        result
    }

    async fn on_block_found_inner(
        &self,
        block_height: i32,
        actual: &ActualCoinbase,
        snapshot: Option<StoredWeightSnapshot>,
        payouts_fingerprint: Option<[u8; 32]>,
    ) -> Result<ApplyDistributionResult, EngineError> {
        // 1. Snapshot source: the blob the Core resolved at found-time,
        //    else a late read under the fingerprint. The late read is the
        //    fallback for a Redis blip at the found instant, not the
        //    design — by now the key has usually TTL'd out (see
        //    `weight_snapshot_for_block_found`).
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                let fingerprint = payouts_fingerprint
                    .filter(|fp| fp != &[0u8; 32])
                    .ok_or(EngineError::NoPayoutFingerprint { block_height })?;
                self.weight_snapshot_for_block_found(&fingerprint)
                    .await
                    .map_err(|e| match e {
                        // At apply time the missing key means the TTL won:
                        // report it as the block-scoped failure the
                        // operator reprocess keys off.
                        EngineError::SnapshotMissingForPayouts => {
                            EngineError::SnapshotMissing { block_height }
                        }
                        other => other,
                    })?
            }
        };

        // The one hard gate: a coinbase that pays less than its own
        // subsidy destroyed money it was entitled to. No mempool drift,
        // no stale projection base and no job-declaring client's own
        // template can produce that, so it never fires on a healthy
        // block — and a block that DID do it is not one to book blind.
        let subsidy = block_subsidy_sats(block_height, self.inner.config.subsidy_halving_interval);
        if actual.total_value_sats < subsidy {
            error!(
                subsidy,
                actual_reward = actual.total_value_sats,
                block_height,
                "PPLNS block coinbase pays less than the block subsidy — refusing to book"
            );
            return Err(EngineError::RevenueBelowSubsidy {
                block_height,
                actual_reward: actual.total_value_sats,
                subsidy,
            });
        }
        // 2. Settle. The balance write is absolute (`current + delta`), so
        //    `current` MUST be read under `FOR UPDATE` in the same
        //    transaction that writes it — otherwise the daily dust sweep,
        //    whose targets are exactly the balance-only entries a
        //    distribution carries, can commit between the two and have its
        //    work silently undone. The Redis window read stays OUTSIDE the
        //    transaction: it only decides which addresses get a 0-sat
        //    late-arriver audit row, and a Redis stall must not hold a PG
        //    transaction open.
        // Which address did the coinbase pay each ledger key? For a static
        // miner the two are the same string and always were; for a rotating one
        // the ledger key is a `payout_id` and the paid address is derived at
        // THIS height. Resolved here, after the snapshot is in hand, because the
        // fallback branch above is where the caller does not know the entries.
        //
        // A negative height is not a derivation index; `require_height` refuses
        // it on the next line rather than letting it settle as height 0.
        let derivation_height = u32::try_from(block_height).unwrap_or(0);
        let paid_at = self
            .identity_resolver()
            .paid_at_height(&Self::ledger_keys(&snapshot), derivation_height)
            .await?;
        paid_at.require_height(block_height)?;

        let now_ms = chrono::Utc::now().timestamp_millis();
        let current_window = self.inner.window.read_window_by_address().await?;
        let addresses = Self::addresses_to_settle(&snapshot, actual, &paid_at);

        let mut tx = self.inner.pool.begin().await.map_err(LedgerError::from)?;
        let existing: HashMap<String, PplnsBalanceRow> =
            bp_db::find_pplns_balances_for_addresses_locked(&mut *tx, &addresses)
                .await?
                .into_iter()
                .map(|r| (r.address.as_str().to_string(), r))
                .collect();
        let (audit_rows, balance_writes) = Self::build_writes_from_weight_snapshot(
            &snapshot,
            &current_window,
            actual,
            &existing,
            &paid_at,
        )?;
        let outcome =
            apply_distribution(&mut tx, block_height, &audit_rows, &balance_writes, now_ms).await?;
        tx.commit().await.map_err(LedgerError::from)?;

        // The weight snapshot is NOT consumed: it legitimately serves
        // every block built from its distribution (settlement is a delta
        // from the REAL coinbase). It expires by TTL.
        self.inner.distribution_builder.invalidate_all();

        info!(
            block_height,
            history_inserted = outcome.history_inserted,
            balances_affected = outcome.balances_affected,
            "pplns on_block_found applied"
        );
        Ok(outcome)
    }

    /// Every address this block settles, in the order the balance rows
    /// must be LOCKED.
    ///
    /// Sorted, and that is load-bearing: `FOR UPDATE` acquires row locks
    /// in the order the plan emits them, so a stable ordering here (and
    /// the matching `ORDER BY address` in the query) is what keeps two
    /// transactions touching the same two rows from deadlocking. The set
    /// used to come straight out of a `HashSet`, i.e. a different order
    /// every run.
    fn addresses_to_settle(
        snapshot: &StoredWeightSnapshot,
        actual: &ActualCoinbase,
        paid_at: &PaidAtHeight,
    ) -> Vec<String> {
        let mut set: std::collections::HashSet<String> =
            snapshot.entries.iter().map(|e| e.address.clone()).collect();
        // Paid addresses outside the snapshot are settled too (they can
        // only be 0-value script matches or operator surprises — logged
        // in the builder — but the lifetime totals must not miss them).
        //
        // A paid address an entry CLAIMS is not one of those: a rotating
        // miner's row lives under its `payout_id`, already in the set above, and
        // locking the derived address as well would create a second ledger row
        // for the same miner — a new one every block, since the address moves
        // with the height. For a static entry the two strings are equal, so this
        // filter drops nothing that the `HashSet` was not already deduplicating.
        set.extend(
            actual
                .paid_by_address
                .keys()
                .filter(|addr| !paid_at.claims(addr))
                .cloned(),
        );
        set.remove(&snapshot.fee_address);
        let mut addresses: Vec<String> = set.into_iter().collect();
        addresses.sort();
        addresses
    }

    /// The ledger keys this snapshot settles, in entry order — what the
    /// paid-address resolver is asked about.
    fn ledger_keys(snapshot: &StoredWeightSnapshot) -> Vec<String> {
        snapshot.entries.iter().map(|e| e.address.clone()).collect()
    }

    /// The weight-model settlement: per snapshot entry compute the
    /// claim from the raw inputs (`claim_sats(score, S, fee, T)`), read
    /// what the coinbase actually paid the address, and book the
    /// difference as a balance DELTA against the current ledger.
    ///
    /// Every case reduces to that one rule: an exactly-paid miner books
    /// `0`; a dust-pruned or blockspace-folded miner books the full
    /// claim as credit; a debt-carrying miner's claim pays the debt
    /// down; an overpaid miner (revenue drifted below the projection)
    /// books the overshoot as debt. The pool/fee output has no balance
    /// row — `T − Σ claims` is the pool's by construction.
    ///
    /// Pure: `existing` comes in already read and LOCKED by the caller's
    /// transaction. It used to do that read itself, from the pool and
    /// outside the writing transaction, which is precisely the window the
    /// dust sweep could commit into.
    ///
    /// `paid_at` is what makes "read what the coinbase actually paid the
    /// address" work for a rotating identity: the ledger key is a `payout_id`,
    /// which no coinbase output can ever render to, so the lookup goes through
    /// the address that key was paid under at this height. Every other use of
    /// the key — the balance row, the audit row, the `existing` lookup — stays on
    /// the height-invariant key, which is the whole point of the split.
    fn build_writes_from_weight_snapshot(
        snapshot: &StoredWeightSnapshot,
        current_window: &HashMap<String, f64>,
        actual: &ActualCoinbase,
        existing: &HashMap<String, PplnsBalanceRow>,
        paid_at: &PaidAtHeight,
    ) -> Result<(Vec<AuditRow>, Vec<BalanceWrite>), EngineError> {
        let t = actual.total_value_sats;

        let mut audit_rows: Vec<AuditRow> = Vec::new();
        let mut balance_writes: Vec<BalanceWrite> = Vec::new();
        let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();

        // The promises this distribution carried, recomputed exactly as
        // the build did. Subtracting them is what keeps the ledger from
        // inventing money: the coinbase paid those satoshis out of this
        // same pot, so a miner without a promise of its own earns a
        // share of the REST — charging it the full pot would credit it
        // the others' promises on every block.
        let extras_total = snapshot.extras_total();

        for entry in &snapshot.entries {
            if entry.address == snapshot.fee_address {
                // The fee address should never appear as a miner entry
                // (the builder routes the pool share via weight_P), but
                // if it does, its payment attribution is inseparable
                // from the pool output — skip rather than misbook.
                warn!(
                    address = %entry.address,
                    "weight settlement: fee address doubles as miner entry — skipping its row"
                );
                continue;
            }
            let claim = claim_sats(
                entry.score_weight,
                snapshot.score_total,
                snapshot.fee_ppm,
                t,
                extras_total,
            );
            // No fallback to `entry.address` here on purpose: a rotating key
            // missing from the attribution would find nothing in
            // `paid_by_address`, book `delta == claim`, and credit the miner its
            // whole claim on top of the payment it already received.
            let paid_address = paid_at.paid_address(&entry.address).ok_or_else(|| {
                PaidAtHeightError::NotCoveringSnapshot {
                    payout_id: entry.address.clone(),
                }
            })?;
            let paid = actual
                .paid_by_address
                .get(paid_address)
                .copied()
                .unwrap_or(0);
            let delta = claim - paid as i64;

            let current = existing
                .get(&entry.address)
                .map(|r| r.balance_sats.0)
                .unwrap_or(0);
            let prev_total_paid = existing
                .get(&entry.address)
                .map(|r| r.total_paid_sats.0)
                .unwrap_or(0);

            let addr_id = AddressId::new(entry.address.clone())?;
            if paid > 0 {
                audit_rows.push(AuditRow {
                    address: addr_id.clone(),
                    paid_sats: Sats(paid as i64),
                    percent: if t > 0 {
                        (paid as f64 / t as f64 * 100.0) as f32
                    } else {
                        0.0
                    },
                    row_type: PayoutRowType::Coinbase,
                });
            } else if delta != 0 {
                audit_rows.push(pending_row(addr_id.clone(), Sats(delta)));
            } else {
                // No payment, no ledger movement — nothing to record.
                continue;
            }
            emitted.insert(entry.address.clone());
            balance_writes.push(BalanceWrite {
                address: addr_id,
                balance_sats: Sats(current + delta),
                total_paid_sats: Sats(prev_total_paid + paid as i64),
            });
        }

        // Coinbase outputs paying an address the snapshot does not know.
        // With positional §7.1 validation this cannot happen for value-
        // carrying outputs; surface loudly if it ever does, and book the
        // payment into the lifetime total without inventing a claim.
        for (addr_str, paid) in &actual.paid_by_address {
            if *paid == 0 || emitted.contains(addr_str) || *addr_str == snapshot.fee_address {
                continue;
            }
            // `claims` and not a scan of `snapshot.entries`: a rotating entry's
            // key is a `payout_id` and can never equal the address the coinbase
            // paid it, so the scan would call every rotating payout an outsider
            // and mint a second, height-shaped row debiting the miner for its own
            // payout. For a static entry the two questions have the same answer.
            if !paid_at.claims(addr_str) {
                warn!(
                    address = %addr_str,
                    paid,
                    "weight settlement: coinbase paid an address outside the distribution"
                );
                let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                    continue;
                };
                let current = existing
                    .get(addr_str)
                    .map(|r| r.balance_sats.0)
                    .unwrap_or(0);
                let prev_total_paid = existing
                    .get(addr_str)
                    .map(|r| r.total_paid_sats.0)
                    .unwrap_or(0);
                audit_rows.push(AuditRow {
                    address: addr_id.clone(),
                    paid_sats: Sats(*paid as i64),
                    percent: if t > 0 {
                        (*paid as f64 / t as f64 * 100.0) as f32
                    } else {
                        0.0
                    },
                    row_type: PayoutRowType::Coinbase,
                });
                emitted.insert(addr_str.clone());
                balance_writes.push(BalanceWrite {
                    address: addr_id,
                    balance_sats: Sats(current - *paid as i64),
                    total_paid_sats: Sats(prev_total_paid + *paid as i64),
                });
            }
        }

        // Late arrivers: active in the window, unknown to the snapshot.
        for addr_str in current_window.keys() {
            if emitted.contains(addr_str)
                || addr_str == &snapshot.fee_address
                || snapshot.entries.iter().any(|e| &e.address == addr_str)
            {
                continue;
            }
            let Ok(addr_id) = AddressId::new(addr_str.clone()) else {
                continue;
            };
            audit_rows.push(pending_row(addr_id, Sats(0)));
            emitted.insert(addr_str.clone());
        }

        Ok((audit_rows, balance_writes))
    }

    /// Drop one cached distribution entry. Called by the engine itself
    /// on share-record; exposed so manual admin tooling can force a
    /// recompute too.
    pub fn invalidate_distribution(&self, block_reward_sats: u64) {
        self.inner
            .distribution_builder
            .invalidate(block_reward_sats);
    }

    /// Signal both background tasks to exit. Best-effort: the tasks
    /// drain their final state (touch buffer flush, no final sweep)
    /// before returning. The engine remains usable for synchronous
    /// API calls until the underlying pool/redis connections are
    /// dropped.
    pub fn shutdown(&self) {
        // `watch::Sender::send` returns Err if all receivers have
        // dropped — fine, the tasks already exited.
        let _ = self.inner.cancel_tx.send(true);
    }

    // ── Accessors for reader.rs / hooks.rs ──────────────────────────

    pub fn config(&self) -> &PplnsEngineConfig {
        &self.inner.config
    }

    pub fn pool(&self) -> &PgPool {
        &self.inner.pool
    }

    pub fn window(&self) -> &WindowStore {
        &self.inner.window
    }

    pub fn touch_buffer(&self) -> &Arc<TouchBuffer> {
        &self.inner.touch_buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_carries_source_variants() {
        // Sanity: confirm the `From` impls compose. No runtime needed.
        fn _accepts_db(e: DbError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_window(e: WindowError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_ledger(e: LedgerError) -> EngineError {
            EngineError::from(e)
        }
        fn _accepts_sweep(e: SweepError) -> EngineError {
            EngineError::from(e)
        }
    }

    #[test]
    fn block_found_in_progress_error_is_displayable() {
        let e = EngineError::BlockFoundInProgress;
        let s = format!("{e}");
        assert!(s.contains("in flight"), "got: {s}");
    }

    #[test]
    fn snapshot_missing_error_carries_block_height() {
        let e = EngineError::SnapshotMissing { block_height: 9001 };
        let s = format!("{e}");
        assert!(s.contains("9001"), "got: {s}");
    }

    // ── Rotating identities at settlement (plan Phase 4a) ──────────────
    //
    // These call the pure settlement function directly. The money question
    // is decided entirely inside it, and the block-height/attribution pair
    // it is handed is the only new input, so a DB-backed test would add a
    // container dependency without adding evidence.

    use bitcoin::{absolute::LockTime, transaction::Version, Address, Amount, Network, ScriptBuf};
    use bp_coinbase_snapshot::PaidAtHeight;
    use bp_payout_descriptor::RotatingPayout;

    /// BIP-32 test-vector xpubs (published, no funds).
    const XPUB_A: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const XPUB_B: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
    const NETWORK: Network = Network::Regtest;
    const HEIGHT: i32 = 840_000;

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

    fn entry(address: &str, score_weight: u64) -> bp_coinbase_snapshot::WeightSnapshotEntry {
        bp_coinbase_snapshot::WeightSnapshotEntry {
            address: address.to_string(),
            score_weight,
            balance_sats: 0,
            wire_weight: 1_000,
            dust_limit: 546,
        }
    }

    /// A coinbase paying `(script, sats)` after the pool output.
    fn coinbase(pool: ScriptBuf, outputs: Vec<(ScriptBuf, u64)>) -> bitcoin::Transaction {
        let mut output = vec![bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: pool,
        }];
        output.extend(
            outputs
                .into_iter()
                .map(|(script_pubkey, sats)| bitcoin::TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey,
                }),
        );
        bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    fn script_for(address: &str) -> ScriptBuf {
        address
            .parse::<Address<_>>()
            .expect("a real address")
            .assume_checked()
            .script_pubkey()
    }

    /// **The Phase 4a money test.** A rotating miner is paid at the address its
    /// descriptor derives for THIS block, and settles under its height-invariant
    /// `payout_id` — one row, the right amount, and nothing minted under the
    /// derived address.
    ///
    /// Without the attribution the same inputs produce two wrong rows in
    /// opposite directions: a full-claim CREDIT under the `payout_id` (because
    /// `paid_by_address` has no such key) and a DEBIT under a `bcrt1…` that
    /// changes every block. Both are asserted absent.
    #[test]
    fn a_rotating_entry_settles_under_its_payout_id_and_mints_no_second_row() {
        let payout = RotatingPayout::from_xpub_str(XPUB_A).expect("intake");
        let payout_id = payout.payout_id().as_str().to_string();
        let derived = payout
            .address_at(NETWORK, HEIGHT as u32)
            .expect("derives")
            .to_string();
        let static_miner = real_address(XPUB_B, 7);
        let fee_address = real_address(XPUB_B, 8);

        // Preconditions that pin the shape this test means to build. Without
        // them the assertions below could all hold for a distribution that
        // never paid anybody.
        assert_ne!(payout_id, derived, "the ledger key is not the paid address");
        assert!(
            !payout_id.starts_with("bcrt1"),
            "and cannot be mistaken for one"
        );

        let snapshot = StoredWeightSnapshot {
            entries: vec![entry(&payout_id, 500_000), entry(&static_miner, 500_000)],
            weight_p: 0,
            fee_ppm: 0,
            fee_address: fee_address.clone(),
            reference_revenue_sats: 0,
            score_total: 1_000_000,
        };

        // The block pays each miner half of a 100_000-sat coinbase: the
        // rotating one at its derived address, the static one at its own.
        let tx = coinbase(
            script_for(&fee_address),
            vec![
                (script_for(&derived), 50_000),
                (script_for(&static_miner), 50_000),
            ],
        );
        let actual = ActualCoinbase::from_coinbase(&tx, NETWORK);
        assert_eq!(
            actual.paid_by_address.get(&derived).copied(),
            Some(50_000),
            "precondition: the coinbase really paid the derived address"
        );
        assert!(
            !actual.paid_by_address.contains_key(&payout_id),
            "precondition: and nothing is keyed on the payout_id"
        );

        let identities = [
            payout.clone().into_payout_identity(),
            bp_common::PayoutIdentity::static_address_verbatim(static_miner.clone()),
        ];
        let paid_at =
            PaidAtHeight::resolve(identities.iter(), NETWORK, HEIGHT as u32).expect("resolve");

        let (audit_rows, balance_writes) = PplnsEngine::build_writes_from_weight_snapshot(
            &snapshot,
            &HashMap::new(),
            &actual,
            &HashMap::new(),
            &paid_at,
        )
        .expect("settles");

        // Each miner claims half of 100_000 with no fee, and was paid exactly
        // that: delta 0, booked as a Coinbase row for what it received.
        let expected_claim = claim_sats(500_000, 1_000_000, 0, actual.total_value_sats, 0);
        assert_eq!(
            expected_claim, 50_000,
            "precondition: the claim is the payment"
        );

        let rotating_row = audit_rows
            .iter()
            .find(|r| r.address.as_str() == payout_id)
            .expect("a row under the payout_id");
        assert_eq!(
            rotating_row.paid_sats,
            Sats(50_000),
            "the rotating miner's payment must be attributed to its ledger key"
        );
        assert_eq!(rotating_row.row_type, PayoutRowType::Coinbase);
        assert!(
            !audit_rows.iter().any(|r| r.address.as_str() == derived),
            "no row may be minted under the derived address: {:?}",
            audit_rows
                .iter()
                .map(|r| r.address.as_str())
                .collect::<Vec<_>>()
        );

        let rotating_write = balance_writes
            .iter()
            .find(|w| w.address.as_str() == payout_id)
            .expect("a balance write under the payout_id");
        assert_eq!(
            rotating_write.balance_sats,
            Sats(0),
            "paid exactly its claim, so the balance does not move"
        );
        assert_eq!(rotating_write.total_paid_sats, Sats(50_000));
        assert_eq!(balance_writes.len(), 2, "one row per miner, no extras");
    }

    /// The same distribution settled against a block that paid the address the
    /// identity derives for a DIFFERENT height. The rotating miner was not paid
    /// by this block, so it books its whole claim as credit — and the address
    /// that WAS paid is an outsider.
    ///
    /// This is the control that shows the test above is measuring attribution
    /// and not just "two entries produce two rows".
    #[test]
    fn a_payment_derived_for_another_height_is_not_this_blocks_payment() {
        let payout = RotatingPayout::from_xpub_str(XPUB_A).expect("intake");
        let payout_id = payout.payout_id().as_str().to_string();
        let other_height = payout
            .address_at(NETWORK, HEIGHT as u32 + 1)
            .expect("derives")
            .to_string();
        let fee_address = real_address(XPUB_B, 8);

        let snapshot = StoredWeightSnapshot {
            entries: vec![entry(&payout_id, 1_000_000)],
            weight_p: 0,
            fee_ppm: 0,
            fee_address: fee_address.clone(),
            reference_revenue_sats: 0,
            score_total: 1_000_000,
        };
        let tx = coinbase(
            script_for(&fee_address),
            vec![(script_for(&other_height), 100_000)],
        );
        let actual = ActualCoinbase::from_coinbase(&tx, NETWORK);

        let identities = [payout.into_payout_identity()];
        let paid_at =
            PaidAtHeight::resolve(identities.iter(), NETWORK, HEIGHT as u32).expect("resolve");
        let (audit_rows, _) = PplnsEngine::build_writes_from_weight_snapshot(
            &snapshot,
            &HashMap::new(),
            &actual,
            &HashMap::new(),
            &paid_at,
        )
        .expect("settles");

        let own = audit_rows
            .iter()
            .find(|r| r.address.as_str() == payout_id)
            .expect("a row under the payout_id");
        assert_eq!(
            own.row_type,
            PayoutRowType::Pending,
            "unpaid by this block, so the claim is owed, not recorded as paid"
        );
        assert!(
            audit_rows
                .iter()
                .any(|r| r.address.as_str() == other_height),
            "and the address this block DID pay is booked as an outsider"
        );
    }

    /// An entry the attribution does not cover is refused, not settled as
    /// "paid nothing" — which would credit the miner its whole claim on top of
    /// what the coinbase already paid it.
    #[test]
    fn an_unattributed_entry_refuses_the_block() {
        let payout_id = RotatingPayout::from_xpub_str(XPUB_A)
            .expect("intake")
            .payout_id()
            .as_str()
            .to_string();
        let fee_address = real_address(XPUB_B, 8);
        let snapshot = StoredWeightSnapshot {
            entries: vec![entry(&payout_id, 1_000_000)],
            weight_p: 0,
            fee_ppm: 0,
            fee_address,
            reference_revenue_sats: 0,
            score_total: 1_000_000,
        };
        let actual = ActualCoinbase {
            paid_by_address: HashMap::new(),
            pool_paid_sats: 0,
            total_value_sats: 100_000,
        };

        let err = PplnsEngine::build_writes_from_weight_snapshot(
            &snapshot,
            &HashMap::new(),
            &actual,
            &HashMap::new(),
            // Empty: nothing resolved this entry.
            &PaidAtHeight::static_only(HEIGHT as u32),
        )
        .expect_err("an unattributed entry must refuse the block");
        assert!(
            matches!(
                err,
                EngineError::PaymentAttribution(
                    bp_coinbase_snapshot::PaidAtHeightError::NotCoveringSnapshot { .. }
                )
            ),
            "got {err:?}"
        );
        assert!(
            err.is_terminal(),
            "a map that misses its own snapshot is a bug"
        );
    }
}
