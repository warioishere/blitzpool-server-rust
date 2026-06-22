// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime driver for the coinbase-budget autoscaler.
//!
//! Glues three pieces the pure control core ([`bp_pplns_engine::autoscale`])
//! cannot reach on its own:
//!
//! - the **live budget handle** the PPLNS distribution builder reads per
//!   template (pressure samples flow out, new budgets flow in);
//! - **bitcoin-core's reservation** via the TDP handle — coupled to the
//!   trimmer budget in the race-safe order so a found block is never rejected;
//! - **Redis persistence** so the live value survives a restart (otherwise a
//!   reboot resets to the floor and the autoscaler re-climbs — itself hopping).
//!
//! ## Race-safe coupling
//!
//! Invariant: *trimmer budget ≤ bitcoin-core reservation at every instant.*
//! - **increase** (the growth case): raise core's reservation FIRST, then the
//!   trimmer budget — a fresh job built after the change always fits.
//! - **decrease**: lower the trimmer budget FIRST, then core — the trimmer
//!   never emits more than the shrinking reservation.
//!
//! This is safe across in-flight templates because a coinbase is baked at
//! job-build time and snapshot-replayed at block-found: an already-issued job
//! keeps its old (smaller) coinbase regardless of a later budget bump.

use std::time::Duration;

use redis::aio::ConnectionManager;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use bp_coinbase_snapshot::{read_coinbase_budget, write_coinbase_budget};
use bp_config::CoinbaseAutoscaleConfig;
use bp_pplns_engine::autoscale::{AutoscaleDecision, AutoscaleParams, Autoscaler, LiveBudget};
use bp_pplns_engine::engine::PplnsEngine;
use bp_template_distribution::TdpHandle;

/// Redis key holding the persisted live coinbase weight budget. Plain STRING,
/// no TTL — must outlive any single pool process.
pub(crate) const BUDGET_KEY: &str = "pplns:coinbase_budget";

/// Shutdown handle for the spawned driver task.
pub(crate) struct AutoscalerHandle {
    cancel_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl AutoscalerHandle {
    /// Signal the driver to stop and await its exit.
    pub(crate) async fn shutdown(self) {
        let _ = self.cancel_tx.send(true);
        let _ = self.join.await;
    }
}

/// Translate the validated TOML config + floor into the control core's params.
fn params_from_config(cfg: &CoinbaseAutoscaleConfig, floor: u32) -> AutoscaleParams {
    AutoscaleParams {
        floor,
        ceiling: cfg.max_weight_budget,
        up_threshold: cfg.up_threshold,
        down_threshold: cfg.down_threshold,
        step_factor: cfg.step_factor,
        up_debounce: cfg.up_debounce,
        down_debounce: cfg.down_debounce,
        cooldown_secs: cfg.cooldown_secs,
    }
}

/// Apply `new_budget`, coupling the trimmer budget to bitcoin-core's
/// reservation in the race-safe order, then persist. Returns `true` if the
/// change fully took effect (so the caller can resync the control core's
/// belief on partial failure).
async fn apply_budget(
    new_budget: u32,
    live: &LiveBudget,
    engine: &PplnsEngine,
    tdp: &TdpHandle,
    redis: &mut ConnectionManager,
) -> bool {
    let current = live.get();
    if new_budget == current {
        return true;
    }
    let c = crate::boot::tdp_constraint_for_budget(new_budget);

    let applied = if new_budget > current {
        // INCREASE: bitcoin-core reservation first.
        match tdp
            .set_coinbase_constraints(c.max_additional_size, c.max_additional_sigops)
            .await
        {
            Ok(()) => {
                live.set(new_budget);
                engine.invalidate_distribution_cache();
                true
            }
            Err(e) => {
                error!(error = %e, current, new_budget,
                    "autoscale: raising bitcoin-core reservation failed; leaving budget unchanged");
                false
            }
        }
    } else {
        // DECREASE: trimmer budget first (it must never exceed the reservation).
        live.set(new_budget);
        engine.invalidate_distribution_cache();
        match tdp
            .set_coinbase_constraints(c.max_additional_size, c.max_additional_sigops)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                // Trimmer already lowered; core still reserves the larger amount
                // — SAFE (just wastes a little block space) until the next boot
                // reconcile re-advertises. Persist the new (binding) value.
                warn!(error = %e, current, new_budget,
                    "autoscale: lowering bitcoin-core reservation failed; trimmer lowered anyway (core over-reserves, safe)");
                true
            }
        }
    };

    if applied {
        if let Err(e) = write_coinbase_budget(redis, BUDGET_KEY, new_budget).await {
            warn!(error = %e, new_budget,
                "autoscale: persisting budget to Redis failed; runtime value still applied");
        }
        info!(
            current,
            new_budget, "autoscale: coinbase weight budget changed"
        );
    }
    applied
}

/// Boot reconcile: adopt the persisted budget (if any), clamped to
/// `[floor, ceiling]`, re-advertising it to bitcoin-core so the reservation
/// matches the trimmer after a restart. Returns the budget now in effect.
async fn reconcile_at_boot(
    params: &AutoscaleParams,
    live: &LiveBudget,
    engine: &PplnsEngine,
    tdp: &TdpHandle,
    redis: &mut ConnectionManager,
) -> u32 {
    match read_coinbase_budget(redis, BUDGET_KEY).await {
        Ok(Some(persisted)) => {
            let clamped = persisted.clamp(params.floor, params.ceiling);
            let seed = live.get();
            if clamped != seed {
                info!(
                    persisted,
                    clamped,
                    seed,
                    "autoscale: adopting persisted budget at boot (re-advertising to bitcoin-core)"
                );
                apply_budget(clamped, live, engine, tdp, redis).await;
            } else if persisted != clamped {
                // Persisted value was out of the current [floor,ceiling] band
                // (operator narrowed it across a restart); rewrite the clamped.
                let _ = write_coinbase_budget(redis, BUDGET_KEY, clamped).await;
            }
            live.get()
        }
        Ok(None) => {
            // First boot: the engine seeded `live` from config and `spawn_tdp`
            // advertised the matching reservation already. Persist the seed so
            // subsequent boots are deterministic.
            let seed = live.get();
            if let Err(e) = write_coinbase_budget(redis, BUDGET_KEY, seed).await {
                warn!(error = %e, seed, "autoscale: persisting boot seed failed");
            }
            seed
        }
        Err(e) => {
            warn!(error = %e, "autoscale: Redis read failed at boot; using config seed");
            live.get()
        }
    }
}

/// Gate + spawn the autoscaler. Returns `None` (autoscaling off, budget stays
/// fixed at `coinbase_weight_budget`) when the feature isn't configured, is
/// disabled, has no TDP handle to couple to, or is misconfigured. A misconfig
/// is logged loudly but **never fatal** — a typo in a threshold must not stop
/// the pool from mining; it just falls back to the fixed (safe) budget.
pub(crate) async fn maybe_spawn(
    pplns_cfg: Option<&bp_config::PplnsConfig>,
    engine: Option<&PplnsEngine>,
    tdp: Option<&TdpHandle>,
    redis: &ConnectionManager,
) -> Option<AutoscalerHandle> {
    let pplns_cfg = pplns_cfg?;
    let auto_cfg = pplns_cfg.coinbase_autoscale.as_ref()?;
    if !auto_cfg.enabled {
        info!("autoscale: section present but enabled=false; coinbase budget stays fixed");
        return None;
    }
    let Some(engine) = engine else {
        warn!("autoscale: enabled but PPLNS engine not running; coinbase budget stays fixed");
        return None;
    };
    let Some(tdp) = tdp else {
        warn!("autoscale: enabled but no TDP handle (--skip-tdp?); cannot couple to bitcoin-core, staying fixed");
        return None;
    };
    if let Err(e) = auto_cfg.validate() {
        error!(error = %e, "autoscale: invalid [pplns.coinbase_autoscale] config; staying fixed");
        return None;
    }
    let floor = pplns_cfg.coinbase_weight_budget;
    if auto_cfg.max_weight_budget <= floor {
        error!(
            floor,
            ceiling = auto_cfg.max_weight_budget,
            "autoscale: max_weight_budget must exceed coinbase_weight_budget (floor); staying fixed"
        );
        return None;
    }
    Some(spawn(auto_cfg, floor, engine.clone(), tdp.clone(), redis.clone()).await)
}

/// Reconcile the persisted budget and spawn the driver task. Caller has already
/// validated `cfg` and confirmed `enabled`, a PPLNS engine, and a TDP handle.
pub(crate) async fn spawn(
    cfg: &CoinbaseAutoscaleConfig,
    floor: u32,
    engine: PplnsEngine,
    tdp: TdpHandle,
    mut redis: ConnectionManager,
) -> AutoscalerHandle {
    let params = params_from_config(cfg, floor);
    let live = engine.coinbase_budget();
    let sample_interval = Duration::from_secs(cfg.sample_interval_secs);

    let effective = reconcile_at_boot(&params, &live, &engine, &tdp, &mut redis).await;
    info!(
        floor = params.floor,
        ceiling = params.ceiling,
        effective,
        up = params.up_threshold,
        down = params.down_threshold,
        step = params.step_factor,
        sample_secs = cfg.sample_interval_secs,
        "autoscale: driver starting"
    );

    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let join = tokio::spawn(async move {
        let mut autoscaler = Autoscaler::new(params, live.get());
        let mut ticker = tokio::time::interval(sample_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let started = tokio::time::Instant::now();
        let mut last_seq = live.sample_seq();

        loop {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    // Skip ticks with no fresh distribution (quiet pool): a
                    // stale sample carries no new information.
                    let seq = live.sample_seq();
                    if seq == last_seq {
                        continue;
                    }
                    last_seq = seq;
                    let Some(sample) = live.latest_sample() else { continue; };
                    let now_secs = started.elapsed().as_secs();
                    if let AutoscaleDecision::SetBudget(n) =
                        autoscaler.observe(sample.utilization(), now_secs)
                    {
                        apply_budget(n, &live, &engine, &tdp, &mut redis).await;
                        // Resync the control core to whatever actually took
                        // effect — apply_budget may have aborted on an IPC error,
                        // leaving the real budget below what observe() assumed.
                        autoscaler.set_current_budget(live.get());
                    }
                }
            }
        }
        info!("autoscale: driver task stopped");
    });

    AutoscalerHandle { cancel_tx, join }
}
