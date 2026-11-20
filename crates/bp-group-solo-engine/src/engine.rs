// SPDX-License-Identifier: AGPL-3.0-or-later

//! `GroupSoloEngine`: wires the round store, distribution builder and the
//! calendar round-reset loop. `on_block_found` books the payout history from the
//! block's OWN coinbase, never from what the pool intended to pay.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use bp_common::{AddressId, MiningMode, Sats};
use bp_cron_utils::SystemClock;
use bp_db::{find_group, DbError, PplnsGroupRow};
use bp_group_mgmt::group::{window_duration_ms, PayoutMode, RoundResetPreset};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{ConfigError, GroupSoloEngineConfig};
use crate::distribution::{
    BuiltDistribution, DistributionBuilder, DistributionConfig, DistributionError,
};
use crate::history::{apply_distribution, ApplyDistributionResult, AuditRow, LedgerError};
use crate::reset::{spawn_reset_loop, GroupResetRunner, ResetError};

use crate::round::{GroupRoundStore, RoundAtFind, RoundError, WINDOW_BUCKET_MS};

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
    #[error("group {0} does not exist")]
    GroupNotFound(Uuid),
}

impl EngineError {
    /// Errors that fail the same way on every retry, so the confirmation
    /// watcher surfaces them once instead of re-applying forever. The block
    /// is not lost: the operator reprocess books it from its own coinbase.
    pub fn is_terminal(&self) -> bool {
        match self {
            EngineError::Config(_) | EngineError::GroupNotFound(_) => true,
            // `LedgerError` decides, so this engine and PPLNS cannot disagree.
            EngineError::Ledger(e) => e.is_terminal(),
            // Infrastructure: these clear on their own.
            EngineError::Redis(_)
            | EngineError::Round(_)
            | EngineError::Db(_)
            | EngineError::Reset(_)
            | EngineError::Distribution(_) => false,
        }
    }
}

/// One found block of a group as its booking sees it.
#[derive(Clone, Debug)]
pub struct FoundGroupBlock<'a> {
    pub height: i32,
    /// Block hash; each block is taken out of the round once per hash.
    pub hash: &'a str,
    /// The group's state at the find, which booking takes out of the round.
    pub round_at_find: RoundAtFind,
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
    /// Stops the round-reset loop (only running where background tasks are).
    cancel_tx: watch::Sender<bool>,
    /// Keeps Postgres off the per-share path. A group's payout mode never
    /// changes, so a looked-up mode is kept for the process's life; the
    /// editable window length is read where it is used.
    mode_cache: StdMutex<HashMap<Uuid, PayoutMode>>,
    /// Highest bucket already trimmed by the record path; buckets only age out
    /// whole, so trimming once per new bucket suffices. The payout read
    /// re-trims anyway, so this only bounds Redis and never affects correctness.
    window_trim_watermark: StdMutex<HashMap<Uuid, i64>>,
}

/// Trim on a group's first share (cold start catches up any aging) and when a
/// share opens a strictly newer bucket; skip same-bucket and older shares.
fn should_trim_on_bucket(watermark: Option<i64>, bucket_id: i64) -> bool {
    match watermark {
        Some(last) => bucket_id > last,
        None => true,
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

impl GroupSoloEngine {
    /// Validate config, wire dependencies, and run the calendar round-reset
    /// loop.
    pub async fn spawn(
        config: GroupSoloEngineConfig,
        redis: ConnectionManager,
        pool: PgPool,
    ) -> Result<Self, EngineError> {
        Self::spawn_inner(config, redis, pool, true).await
    }

    /// Core-mode constructor without the reset loop: the Core only builds
    /// distributions, and mutating rounds is the Satellite's job.
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
        let distribution_builder = DistributionBuilder::new(pool.clone(), round.clone(), dist_cfg);
        let clock = Arc::new(SystemClock);
        let reset_runner = GroupResetRunner::new(pool.clone(), round.clone(), clock.clone());

        let (cancel_tx, cancel_rx) = watch::channel(false);
        // The JoinHandle is not tracked: the loop exits on `cancel_tx`.
        if background_tasks {
            std::mem::drop(spawn_reset_loop(reset_runner.clone(), cancel_rx));
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
                mode_cache: StdMutex::new(HashMap::new()),
                window_trim_watermark: StdMutex::new(HashMap::new()),
            }),
        })
    }

    /// A group's payout mode, looked up once and then served from the cache.
    /// A failed lookup or a missing group is an error, never a guessed mode: a
    /// Window group's share or kick written to the PROP keys is lost to the
    /// window read.
    async fn resolve_group_mode(&self, group_id: Uuid) -> Result<PayoutMode, EngineError> {
        if let Some(mode) = self
            .inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .get(&group_id)
        {
            return Ok(*mode);
        }
        let group = find_group(&self.inner.pool, group_id)
            .await?
            .ok_or(EngineError::GroupNotFound(group_id))?;
        let mode = group_mode_from_row(&group).0;
        self.inner
            .mode_cache
            .lock()
            .expect("mode_cache poisoned")
            .insert(group_id, mode);
        Ok(mode)
    }

    /// Drop all cached distributions, so the next build reads the round and
    /// the group row again.
    pub fn invalidate_distribution_cache(&self) {
        self.inner.distribution_builder.invalidate_all();
    }

    /// Bumps the watermark and returns `true` per [`should_trim_on_bucket`].
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

    /// Trim once per new bucket; only bounds Redis between payout reads. The
    /// window length is read fresh, once per bucket: it is editable, and a
    /// stale shorter length would drop a bucket a grown window must keep. An
    /// unreadable length skips this trim, as the payout read trims anyway.
    async fn trim_window_at_bucket_boundary(
        &self,
        group_id: Uuid,
        now_ms: i64,
    ) -> Result<(), EngineError> {
        if !self.advance_trim_watermark(group_id, now_ms) {
            return Ok(());
        }
        let window_ms = match find_group(&self.inner.pool, group_id).await {
            Ok(Some(g)) => group_mode_from_row(&g).1,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!(%group_id, error = %e,
                    "group-solo: window length unreadable — trim skipped, the payout read trims");
                return Ok(());
            }
        };
        self.inner
            .round
            .trim_window(&group_id.to_string(), now_ms, window_ms)
            .await?;
        Ok(())
    }

    /// Hot path: an accepted Group-Solo share. Caller has resolved
    /// `group_id` (via the mode-gate adapter in `hooks.rs`). The round
    /// credits `credited`, the difficulty the share counts at; the round's
    /// best share compares `solved`, the difficulty the hash reached.
    pub async fn record_share(
        &self,
        share_id: Option<&str>,
        group_id: Uuid,
        address: &str,
        credited: f64,
        solved: f64,
        timestamp_ms: i64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        let mode = self.resolve_group_mode(group_id).await?;
        let applied = match mode {
            PayoutMode::Prop => {
                self.inner
                    .round
                    .record_share(share_id, &group_key, address, credited, timestamp_ms)
                    .await?
            }
            PayoutMode::Window => {
                let applied = self
                    .inner
                    .round
                    .record_share_windowed(share_id, &group_key, address, credited, timestamp_ms)
                    .await?;
                // Trim against the share's own accept time so an idle group
                // still bounds its window.
                if applied {
                    self.trim_window_at_bucket_boundary(group_id, timestamp_ms)
                        .await?;
                }
                applied
            }
        };
        if !applied {
            // Deduped redelivery: the round already counts this share.
            return Ok(());
        }
        // Best-effort: a missed best-share update is cosmetic.
        if let Err(e) = self
            .inner
            .round
            .update_best_share_if_better(&group_key, address, solved, timestamp_ms)
            .await
        {
            warn!(
                %group_id,
                address,
                error = %e,
                "best-share update failed (cosmetic)"
            );
        }
        // A new share changes the round for every cached (group, reward,
        // finder) triple, so drop the whole distribution cache.
        self.inner.distribution_builder.invalidate_all();
        Ok(())
    }

    /// Count a rejected share. Window mode buckets it on wall-clock time: a
    /// reject carries no accept time, and the lane feeds only the stats view,
    /// so landing in a neighbouring bucket changes no payout.
    pub async fn record_reject(
        &self,
        group_id: Uuid,
        address: &str,
        shares: f64,
    ) -> Result<(), EngineError> {
        let group_key = group_id.to_string();
        let mode = self.resolve_group_mode(group_id).await?;
        match mode {
            PayoutMode::Prop => {
                self.inner
                    .round
                    .record_reject(&group_key, address, shares)
                    .await?;
            }
            PayoutMode::Window => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                self.inner
                    .round
                    .record_reject_windowed(&group_key, address, shares, now_ms)
                    .await?;
                self.trim_window_at_bucket_boundary(group_id, now_ms)
                    .await?;
            }
        }
        Ok(())
    }

    /// Kick flow: drop the address from the group's payout source
    /// (mode-aware, see [`GroupRoundStore::forget_member`]) and forget any
    /// distribution built on it. Returns the diff-1-weighted amount removed.
    pub async fn forget_member(&self, group_id: Uuid, address: &str) -> Result<f64, EngineError> {
        let mode = self.resolve_group_mode(group_id).await?;
        let removed = self
            .inner
            .round
            .forget_member(&group_id.to_string(), address, mode)
            .await?;
        self.inner.distribution_builder.invalidate_all();
        Ok(removed)
    }

    /// Build the current distribution for `(group_id, reward, finder)`.
    pub async fn build_distribution(
        &self,
        group_id: Uuid,
        block_reward_sats: u64,
        finder_address: &AddressId,
    ) -> Result<Arc<BuiltDistribution>, EngineError> {
        self.inner
            .distribution_builder
            .build(group_id, block_reward_sats, finder_address)
            .await
            .map_err(EngineError::Distribution)
    }

    /// Cut the group's state at one of its blocks being found: returns what
    /// the block covers, parked with it so its booking takes out only what
    /// was mined before the find, and starts the best share over now when
    /// `resetRoundOnBlock` is set, so the shares mined while the block waits
    /// for its confirmations can set the next best.
    pub async fn cut_round_at_find(
        &self,
        group_id: Uuid,
        block_hash: &str,
    ) -> Result<RoundAtFind, EngineError> {
        let (mode, window_ms, reset_on_block) = match find_group(&self.inner.pool, group_id).await?
        {
            Some(g) => {
                let (mode, window_ms) = group_mode_from_row(&g);
                (mode, window_ms, g.reset_round_on_block)
            }
            None => (PayoutMode::Prop, 0, false),
        };
        let group_key = group_id.to_string();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let at_find = self
            .inner
            .round
            .read_round_at_find(&group_key, mode, now_ms, window_ms)
            .await?;
        if reset_on_block {
            // Display only: a failed reset must not keep the block from
            // being parked and booked.
            if let Err(e) = self
                .inner
                .round
                .reset_best_share_for(&group_key, block_hash)
                .await
            {
                warn!(%group_id, block_hash, error = %e,
                    "group-solo: best share not started over at the find");
            }
        }
        Ok(at_find)
    }

    /// Book a found block from its OWN coinbase, then take its found-time
    /// state out of the round. No settlement: withheld value goes to the pool
    /// ([`bp_pplns::WithheldValue::ToPool`]), so what the coinbase paid is
    /// the whole truth. Idempotent: the history via the `(groupId,
    /// blockHeight, address)` UNIQUE key, the round via
    /// [`crate::round::key_settled_blocks`], so a redelivery or a retry in any
    /// order takes each block's state out exactly once and leaves the shares
    /// mined since the find.
    pub async fn on_block_found(
        &self,
        group_id: Uuid,
        block: FoundGroupBlock<'_>,
        actual: &bp_coinbase_snapshot::ActualCoinbase,
    ) -> Result<ApplyDistributionResult, EngineError> {
        let group_key = group_id.to_string();
        let block_height = block.height;

        // 2. Mode + reset gate. A dissolved group still gets its history, but
        //    no round state is written back for it.
        let now_ms = chrono::Utc::now().timestamp_millis();
        // A failed read is an error, so the watcher retries the block rather
        // than settle it on a guessed mode.
        let group = find_group(&self.inner.pool, group_id).await?;
        let (mode, reset_on_block, group_live) = match group {
            Some(g) => {
                let (mode, _) = group_mode_from_row(&g);
                (mode, g.reset_round_on_block, g.dissolved_at.is_none())
            }
            None => (PayoutMode::Prop, false, false),
        };
        let at_find = &block.round_at_find;
        let total_shares_in_round: f64 = at_find.payout_shares.values().sum();
        let total_shares_i64 = total_shares_in_round.round() as i64;

        let audit_rows =
            history_rows_from_coinbase(group_id, actual, &at_find.payout_shares, total_shares_i64);

        // 3. Write the history, 4. take the block out of the round, 5. drop
        //    the build cache.
        let outcome = apply_distribution(
            &self.inner.pool,
            group_id,
            block_height,
            &audit_rows,
            now_ms,
        )
        .await?;

        if group_live {
            // An error leaves the block pending: the history is booked, and
            // the retry finishes the settle.
            if !self
                .inner
                .round
                .settle_block(
                    &group_key,
                    block.hash,
                    at_find,
                    subtracts_round(mode, reset_on_block),
                )
                .await?
            {
                info!(%group_id, block_height, block_hash = block.hash,
                    "group-solo: block already taken out of the round — left as it stands");
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

/// Whether booking a block takes its found-time round out of the group. Every
/// block takes its share of the shares-since-block counter out whatever
/// `resetRoundOnBlock` says, so switching the flag on later shows the shares
/// since the last block right away.
fn subtracts_round(mode: PayoutMode, reset_on_block: bool) -> bool {
    match (mode, reset_on_block) {
        (PayoutMode::Prop, true) => true,
        // The window pays from its own age-trimmed span.
        (PayoutMode::Window, _) | (PayoutMode::Prop, false) => false,
    }
}

/// One history row per address the coinbase paid besides the pool output,
/// amounts only from `actual`. An unpaid member gets no row: under
/// [`bp_pplns::WithheldValue::ToPool`] they are owed nothing.
fn history_rows_from_coinbase(
    group_id: Uuid,
    actual: &bp_coinbase_snapshot::ActualCoinbase,
    round_by_addr: &HashMap<String, f64>,
    total_shares_in_round: i64,
) -> Vec<AuditRow> {
    let mut rows: Vec<AuditRow> = Vec::new();

    for (addr_str, paid) in &actual.paid_to_payees(MiningMode::GroupSolo) {
        if *paid == 0 {
            continue;
        }
        let Ok(address) = AddressId::new(addr_str.clone()) else {
            warn!(
                %group_id,
                address = %addr_str,
                paid,
                "group-solo history: coinbase paid an unparseable address — skipping the row"
            );
            continue;
        };
        rows.push(AuditRow {
            address,
            paid_sats: Sats(*paid as i64),
            percent: actual.percent_of_total(*paid),
            shares_in_round: round_by_addr
                .get(addr_str)
                .map(|f| f.round() as i64)
                .unwrap_or(0),
            total_shares_in_round,
        });
    }

    // `paid_by_address` is a map; sort so two runs yield the same order.
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

    /// Stop the round-reset loop. It is not joined, so a shutdown time-out is
    /// the caller's concern.
    pub fn shutdown(&self) {
        // Err only when the loop already exited or never ran.
        let _ = self.inner.cancel_tx.send(true);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_takes_the_round_out_only_for_prop_with_the_flag() {
        assert!(subtracts_round(PayoutMode::Prop, true));
        assert!(!subtracts_round(PayoutMode::Window, true));
        assert!(!subtracts_round(PayoutMode::Prop, false));
        assert!(!subtracts_round(PayoutMode::Window, false));
    }

    #[test]
    fn engine_error_carries_source_variants() {
        fn _from_db(e: DbError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_round(e: RoundError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_ledger(e: LedgerError) -> EngineError {
            EngineError::from(e)
        }
        fn _from_reset(e: ResetError) -> EngineError {
            EngineError::from(e)
        }
    }

    #[test]
    fn trim_watermark_gates_to_new_buckets_only() {
        assert!(should_trim_on_bucket(None, 100));
        assert!(!should_trim_on_bucket(Some(100), 100));
        assert!(should_trim_on_bucket(Some(100), 101));
        assert!(!should_trim_on_bucket(Some(100), 7));
    }

    /// Every paid output besides the pool's becomes a row, the fee address
    /// mining as a member included; a 0-sat entry does not.
    #[test]
    fn history_rows_transcribe_every_paid_output_besides_the_pool() {
        const MEMBER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        const FEE_AS_MEMBER: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        const UNPAID: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let actual = bp_coinbase_snapshot::ActualCoinbase {
            paid_by_address: HashMap::from([
                (MEMBER.to_string(), 200_000_000),
                (FEE_AS_MEMBER.to_string(), 100_000_000),
                (UNPAID.to_string(), 0),
            ]),
            output_zero: None,
            total_value_sats: 312_500_000,
        };
        let rows = history_rows_from_coinbase(Uuid::nil(), &actual, &HashMap::new(), 0);
        let paid: Vec<(&str, i64)> = rows
            .iter()
            .map(|r| (r.address.as_str(), r.paid_sats.0))
            .collect();
        assert_eq!(
            paid,
            vec![(FEE_AS_MEMBER, 100_000_000), (MEMBER, 200_000_000)],
            "the pool output is not in `paid_by_address`; everything else paid is a row"
        );
    }
}
