// SPDX-License-Identifier: AGPL-3.0-or-later

// Workspace lints deny `print_stderr` to keep library diagnostics in
// `tracing`. The binary is the exception: startup errors and hints go to
// stderr too, so the operator sees them under any `RUST_LOG` filter.
#![allow(clippy::print_stderr)]

//! `blitzpool` binary entry-point.
//!
//! Loads `AppConfig`, spawns the foundation handles via [`boot::boot`], the
//! engines via [`engines::spawn`] and the production hooks via
//! [`hooks::spawn`], then wires each subsystem according to the process's
//! roles. The one user-facing knob is `--config <PATH>` (default
//! `./blitzpool.toml`).

// Process-wide allocator: glibc malloc fragments under the pool's
// small-alloc / free pattern (per-connection buffers, query results), and
// jemalloc bounds RSS. Linux only; tikv-jemallocator lacks Windows MSVC.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod api_server;
mod block_confirmation;
mod block_found_consumer;
mod block_reconcile;
mod block_sink;
mod blockparty_reservation;
mod blockparty_service;
mod boot;
mod cache_sync;
mod coinbase_autoscaler;
mod crons;
mod custom_extranonce;
mod device_status;
mod device_status_consumer;
mod device_status_gate;
mod dispatcher;
mod engines;
mod group_service;
mod hooks;
mod jdp;
mod jdp_hooks;
mod listeners;
mod live_mode_marker;
mod live_sessions;
mod network_difficulty;
mod payout_resolver;
mod pending_blocks;
mod redis_backup;
mod rejected_consumer;
mod runtime_diag;
mod satellite_consumer;
mod settlement;
mod stratum;
mod stratum_v1;
mod stratum_v2;
mod stream_monitor;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bp_config::{AppConfig, ConfigError, Role};
use clap::Parser;

use crate::api_server::{ApiServerError, ApiServerHandle};
use crate::boot::{BootError, FoundationHandles};
use crate::crons::CronHandles;
use crate::engines::{EngineError, EngineHandles};
use crate::group_service::GroupServiceSpawnError;
use crate::hooks::{HooksError, ProductionHooks};
use crate::jdp::{JdpHandles, JdpSpawnError};
use crate::listeners::{ListenerHandles, ListenerSpawnError};
use crate::stratum::{StratumHandles, StratumSpawnError};

/// CLI surface, kept deliberately small.
#[derive(Debug, Parser)]
#[command(
    name = "blitzpool",
    about = "Blitzpool — Rust port of the Stratum + PPLNS + Group-Solo Bitcoin mining pool",
    version
)]
struct Cli {
    /// Path to the TOML config file. Falls back to `./blitzpool.toml`
    /// when not set; operators typically point this at a file under
    /// `.local/` so secrets stay out of git.
    #[arg(long, default_value = "./blitzpool.toml")]
    config: PathBuf,

    /// Parse the config file, log the startup summary, and exit
    /// without binding any sockets or contacting any external
    /// service. Useful for CI smoke-checks against a deployment's
    /// `.local/blitzpool.toml`.
    #[arg(long)]
    check_config: bool,

    /// Parse config, spawn the foundation handles (Postgres, Redis,
    /// BitcoinRpc, TDP, GeoIP, Metrics), then exit cleanly. Validates that
    /// a deployment can reach its external dependencies. `--check-config`
    /// short-circuits this.
    #[arg(long)]
    check_boot: bool,

    /// Like `--check-boot` but extends through engine spawning
    /// (PPLNS / Group-Solo / ShareStats / SessionPersistence).
    #[arg(long)]
    check_engines: bool,

    /// Like `--check-engines` but extends through production hook
    /// construction (SMTP / FCM / Web-Push adapter init,
    /// GroupServiceHooks wiring), so any referenced files (FCM
    /// service-account JSON, VAPID PEM) must load.
    #[arg(long)]
    check_hooks: bool,

    /// Like `--check-hooks` but extends through binding the bp-api
    /// HTTP listener on `[api] port`. Exits as soon as the listener
    /// is up — useful for verifying the port isn't already in use.
    #[arg(long)]
    check_api: bool,

    /// Like `--check-api` but extends through binding the unified
    /// SV1+SV2 Stratum listeners and the JDP port. Exits once all
    /// listeners are up.
    #[arg(long)]
    check_stratum: bool,

    /// Skip the bitcoin-rpc `getnetworkinfo` liveness ping during
    /// boot, so the rest of the stack can be validated before the node
    /// is online. Never set in production.
    #[arg(long)]
    skip_bitcoin_rpc_liveness: bool,

    /// Skip the TDP worker spawn entirely, to verify the api / engines
    /// layer without bitcoind. PPLNS network difficulty falls back to 1.0.
    #[arg(long)]
    skip_tdp: bool,

    /// Override the config's deployment roles (comma-separated:
    /// `front,api,payout,stats,notify`), so every container can mount the
    /// same config and differ only by `--roles` / `BLITZPOOL_ROLES`.
    #[arg(long, env = "BLITZPOOL_ROLES", value_delimiter = ',')]
    roles: Vec<Role>,

    /// List the available `redis_state_backup` snapshots (newest first) and
    /// exit. Connects PG only — use to pick a `--restore-at` before a restore.
    #[arg(long)]
    list_redis_backups: bool,

    /// MANUALLY restore the PPLNS + Group-Solo Redis state from a backup
    /// snapshot, then exit. Default is a dry-run (prints the plan); pass
    /// `--restore-force` to actually write. Picks the newest snapshot unless
    /// `--restore-at` is given. Never runs automatically.
    #[arg(long)]
    restore_redis_state: bool,

    /// `captured_at` (epoch ms) of the snapshot to restore. Defaults to the
    /// newest. See `--list-redis-backups`.
    #[arg(long)]
    restore_at: Option<i64>,

    /// Which scope to restore: `all` (default), `pplns`, or `groupsolo`.
    #[arg(long, default_value = "all")]
    restore_scope: String,

    /// Actually perform the restore (`RESTORE ... REPLACE`). Without this the
    /// `--restore-redis-state` run is a dry-run. Overwrites the snapshot's keys
    /// in the live Redis — keys not in the snapshot are left untouched.
    #[arg(long)]
    restore_force: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(config = %cli.config.display(), "loading config");

    let mut cfg = match AppConfig::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!(%err, "config load failed");
            // Plain stderr too, so the operator sees the error under any
            // tracing filter or terminal.
            eprintln!("blitzpool: {err}");
            print_config_error_help(&err);
            return ExitCode::from(2);
        }
    };
    // `--roles` / `BLITZPOOL_ROLES` overrides the config's topology so every
    // container can share one config file and differ only by this env var.
    if !cli.roles.is_empty() {
        tracing::info!(roles = ?cli.roles, "roles overridden from CLI/env");
        cfg.roles = cli.roles.clone();
    }
    log_startup_summary(&cfg);

    if cli.check_config {
        tracing::info!("--check-config given; exiting after successful parse");
        return ExitCode::SUCCESS;
    }

    // Operator one-shot tools for the Redis-state backup: list / restore, then
    // exit. They need only PG (+ Redis for the restore), no roles and no full
    // boot, so they work during recovery while the rest of the stack is down.
    if cli.list_redis_backups || cli.restore_redis_state {
        let db = match boot::spawn_pg(&cfg.database).await {
            Ok(db) => db,
            Err(err) => {
                tracing::error!(%err, "redis-state tool: postgres connect failed");
                eprintln!("blitzpool: postgres connect failed: {err}");
                return ExitCode::from(2);
            }
        };
        if cli.list_redis_backups {
            return match redis_backup::list_snapshots(db.pool()).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("blitzpool: {err}");
                    ExitCode::from(1)
                }
            };
        }
        let scope = match redis_backup::ScopeFilter::parse(&cli.restore_scope) {
            Some(scope) => scope,
            None => {
                eprintln!(
                    "blitzpool: invalid --restore-scope '{}' (expected all|pplns|groupsolo)",
                    cli.restore_scope
                );
                return ExitCode::from(2);
            }
        };
        let mut redis = match boot::spawn_redis(&cfg.redis).await {
            Ok(redis) => redis,
            Err(err) => {
                eprintln!("blitzpool: redis connect failed: {err}");
                return ExitCode::from(2);
            }
        };
        return match redis_backup::run_restore(
            db.pool(),
            &mut redis,
            cli.restore_at,
            scope,
            cli.restore_force,
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("blitzpool: restore failed: {err}");
                ExitCode::from(1)
            }
        };
    }

    // Role validation runs after `--check-config`, since roles usually arrive
    // via BLITZPOOL_ROLES at deploy time. A process with no role does nothing
    // useful, so fail fast instead of booting an inert process.
    if cfg.effective_roles().is_empty() {
        tracing::error!(
            "no roles configured: set BLITZPOOL_ROLES (e.g. =front) or a `roles` \
             list in the config"
        );
        eprintln!(
            "blitzpool: no roles configured — set BLITZPOOL_ROLES (front / api / \
             payout,stats / notify) or a `roles` list in the config"
        );
        return ExitCode::from(2);
    }

    // The front always produces shares onto the Redis stream and a separate
    // payout Satellite consumes them. A process holding both `front` and
    // `payout` would produce shares no one consumes, so fail fast rather than
    // silently drop the money path.
    if cfg.has_role(Role::Front) && cfg.has_role(Role::Payout) {
        tracing::error!(
            "invalid roles: a single process cannot run both `front` and `payout` \
             — run the front (core) and the payout back (satellite) as separate \
             processes"
        );
        eprintln!(
            "blitzpool: invalid roles — `front` and `payout` cannot share a \
             process; run them as separate core + satellite processes"
        );
        return ExitCode::from(2);
    }

    let boot_opts = boot::BootOptions {
        skip_bitcoin_rpc_liveness: cli.skip_bitcoin_rpc_liveness,
        skip_tdp: cli.skip_tdp,
    };
    let handles = match boot::boot(&cfg, boot_opts).await {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(%err, "foundation boot failed");
            eprintln!("blitzpool: {err}");
            print_boot_error_help(&err);
            return ExitCode::from(3);
        }
    };
    log_handles_summary(&handles);

    if cli.check_boot {
        tracing::info!("--check-boot given; exiting after successful boot");
        return ExitCode::SUCCESS;
    }

    let mut engines = match engines::spawn(&cfg, &handles).await {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(%err, "engine spawn failed");
            eprintln!("blitzpool: {err}");
            print_engine_error_help(&err);
            return ExitCode::from(4);
        }
    };
    log_engines_summary(&engines);

    if cli.check_engines {
        tracing::info!("--check-engines given; exiting after successful engine spawn");
        return ExitCode::SUCCESS;
    }

    let production_hooks = match hooks::spawn(&cfg, &handles, &engines).await {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(%err, "hooks spawn failed");
            eprintln!("blitzpool: {err}");
            print_hooks_error_help(&err);
            return ExitCode::from(5);
        }
    };
    log_hooks_summary(&production_hooks);

    if cli.check_hooks {
        tracing::info!("--check-hooks given; exiting after successful hook spawn");
        return ExitCode::SUCCESS;
    }

    // Deployment topology by role (see `Role`). Each subsystem is gated on
    // the role(s) this process runs, so the back-office can be one process
    // (`satellite` = api+payout+stats) or split (e.g. an `api`-only process
    // that serves reads while the `payout` process restarts).
    // - front: Stratum + share producer + block submit + JDP.
    // - api: HTTP API (read-only engines, no consumers/crons).
    // - accounting (payout|stats): engines + stream consumers + ledger apply +
    //   maintenance crons + confirmation watcher.
    // - notify: dispatcher + listeners + notification crons + notify-only
    //   fan-out of the block-found + device-status streams.
    let is_front = cfg.has_role(Role::Front);
    let is_api = cfg.has_role(Role::Api);
    let is_accounting = cfg.has_role(Role::Payout) || cfg.has_role(Role::Stats);
    let is_notify = cfg.has_role(Role::Notify);
    // A back-accounting process consumes the engine streams; the front
    // produces to them.
    let consumes_streams = is_accounting && !is_front;
    let produces_streams = is_front && !cfg.has_role(Role::Payout);
    // A notify process that isn't also the front consumes the notify streams
    // (block-found notify + device-status). A front never carries the notify
    // role, so it produces those events for the notify process to consume.
    let consumes_notify_streams = is_notify && !is_front;
    // An accounting process without the notify role means notifications live
    // in a separate `notify` process; warn so a missing one is noticed.
    if is_accounting && !is_notify {
        tracing::warn!(
            "roles: this process runs accounting WITHOUT notify — notifications \
             (FCM/Web-Push/Telegram/ntfy, block-found + device-status pushes, \
             best-diff/hourly/network-diff crons) are handled by a separate \
             `notify` process. Ensure one is running, or add `notify` here."
        );
    }

    // Telegram + ntfy listener loops + the notification dispatcher belong to the
    // `notify` role. The listeners answer read-commands (/pplns_status …) from
    // the read-only engines; the dispatcher fans out pushes. Off the notify role
    // both collapse to the inert `disabled()` / `None` forms.
    let listeners = if is_notify {
        match listeners::spawn(&cfg, &handles, &engines) {
            Ok(h) => h,
            Err(err) => {
                tracing::error!(%err, "listeners spawn failed");
                eprintln!("blitzpool: {err}");
                print_listener_error_help(&err);
                return ExitCode::from(10);
            }
        }
    } else {
        listeners::ListenerHandles::disabled()
    };
    listeners.log_summary(is_notify);

    // NotificationDispatcher from the four adapters (FCM + Web-Push from
    // hooks; Telegram + ntfy from listeners). `None` when no transport is
    // wired, so the `notify_*` calls become no-ops.
    //
    // Notify-only: all of the dispatcher's drivers run where `notify` runs.
    // Off that role a front produces the block-found + device-status events
    // to streams instead, for the notify process to fan out.
    let dispatcher = if is_notify {
        dispatcher::build(&handles, &production_hooks, &listeners)
    } else {
        None
    };

    // Device-status debounce. Lives wherever the dispatcher lives, so both
    // the in-process sink (combined front+notify) and the stream consumer
    // (split deployment) feed the same instance and a device is judged
    // once, not once per producer.
    let device_status_gate = dispatcher.as_ref().map(|_| {
        let ds = &cfg.notifications.device_status;
        crate::device_status_gate::build(
            bp_notifications::dispatcher::DeviceGateConfig {
                offline_grace: Duration::from_secs(ds.offline_grace_secs),
                online_dwell: Duration::from_secs(ds.online_dwell_secs),
                coalesce_window: Duration::from_secs(ds.coalesce_window_secs),
                recheck_interval: Duration::from_secs(ds.recheck_interval_secs),
            },
            handles.db.pool().clone(),
            handles.redis.clone(),
        )
    });

    let group_service =
        match group_service::spawn(&handles, &production_hooks, &engines.group_solo).await {
            Ok(g) => g,
            Err(err) => {
                tracing::error!(%err, "group-service spawn failed");
                eprintln!("blitzpool: {err}");
                print_group_service_error_help(&err);
                return ExitCode::from(7);
            }
        };

    let blockparty = match blockparty_service::spawn(&cfg, &handles, &group_service).await {
        Ok(bp) => bp,
        Err(err) => {
            tracing::error!(%err, "blockparty spawn failed");
            eprintln!("blitzpool: {err}");
            return ExitCode::from(11);
        }
    };
    if let Some(ref bp) = blockparty {
        // Hook the trait object into EngineHandles so the
        // ProductionPayoutResolver constructed by stratum::spawn picks
        // up the Blockparty arm + the Solo pending-fee guard.
        engines.blockparty = Some(bp.service.clone());
        // Append the share-accept fan-out sink so the first share for a
        // routable admin auto-promotes the party from READY to ACTIVE. Only
        // the front holds an in-process composite; on the satellite the same
        // sink is added to the stream consumer's set below.
        if let Some(accepted_sink) = engines.accepted_sink.as_ref() {
            accepted_sink.push(Arc::new(
                crate::blockparty_service::BlockpartyAcceptedShareSink::new(bp.service.clone()),
            ));
        }
        // Bidirectional mode-collision: PPLNS-group adds refuse addresses
        // already in a Blockparty.
        group_service
            .service
            .set_blockparty_reader(bp.membership_reader.clone());
    }

    // Cross-process routing-cache sync. The API process is the membership
    // writer — attach the notifier so every group/blockparty mutation publishes
    // an invalidation onto the `cache:invalidate` stream. The Front consumes it
    // (spawned below) and rebuilds, so an API-created group/party routes without
    // a Front restart. (A process holding both `api` and `front` publishes
    // and self-consumes; the rebuild is idempotent.)
    if is_api {
        let notifier = Arc::new(crate::cache_sync::StreamCacheNotifier::new(
            handles.redis.clone(),
        ));
        group_service.service.set_change_notifier(notifier.clone());
        if let Some(bp) = blockparty.as_ref() {
            bp.service.set_change_notifier(notifier);
        }
    }

    // The HTTP API is the back-office surface — back-only.
    let api = if is_api {
        match api_server::spawn(
            &cfg,
            &handles,
            &engines,
            &production_hooks,
            &group_service,
            blockparty.as_ref(),
        )
        .await
        {
            Ok(h) => Some(h),
            Err(err) => {
                tracing::error!(%err, "api server bind failed");
                eprintln!("blitzpool: {err}");
                print_api_error_help(&err);
                return ExitCode::from(6);
            }
        }
    } else {
        None
    };
    log_api_summary(api.as_ref(), is_api);

    if cli.check_api {
        tracing::info!("--check-api given; exiting after api phase");
        return ExitCode::SUCCESS;
    }

    // ext 0x0003/Implementation Notes settlement fan-out: every path that
    // books a block tells the local JDP registry (if any) and the
    // `cache:invalidate` stream, since `payout` books while `front` holds the
    // registry. Created ahead of the Stratum listeners, whose block sinks
    // settle on the immediate apply and need the same signal. See
    // `crate::settlement`.
    let settle_signal = crate::settlement::SettlementSignal::new(handles.redis.clone());

    // ONE JDP bridge for the whole process, built here because BOTH servers
    // that use it are spawned below and neither may build its own. It is the
    // only channel between them: the JDP server registers declared jobs and
    // base-protocol allocations, the SV2 mining server resolves a
    // `SetCustomMiningJob` against them. A second bridge would leave the
    // mining side reading a registry nobody writes to.
    let jdp_bridge = stratum_v2::build_bridge();

    // Stratum listeners + share producer are the always-on front — front-only.
    let stratum = if is_front {
        match stratum::spawn(
            &cfg,
            &handles,
            &engines,
            &group_service,
            dispatcher.clone(),
            device_status_gate.clone(),
            settle_signal.clone(),
            jdp_bridge.clone(),
        )
        .await
        {
            Ok(h) => Some(h),
            Err(err) => {
                tracing::error!(%err, "stratum spawn failed");
                eprintln!("blitzpool: {err}");
                print_stratum_error_help(&err);
                return ExitCode::from(8);
            }
        }
    } else {
        None
    };
    log_stratum_summary(stratum.as_ref(), is_front);

    if cli.check_stratum {
        tracing::info!("--check-stratum given; exiting after stratum phase");
        if let Some(stratum) = stratum {
            stratum.shutdown().await;
        }
        return ExitCode::SUCCESS;
    }

    // Background crons split by role: maintenance (kill-dead, cleanups,
    // invitation/join expiry) on the accounting role; the notification crons
    // (network-difficulty, best-difficulty, hourly stats) on the notify role.
    // The best_difficulty + hourly crons seed from address_settings to avoid
    // cold-start notification spam.
    let crons = if is_accounting || is_notify {
        let crons = crons::spawn(
            &handles,
            &production_hooks,
            &listeners,
            dispatcher.clone(),
            is_accounting,
            is_notify,
        )
        .await;
        crons.log_summary();
        Some(crons)
    } else {
        tracing::info!("crons summary: not run on this process (no accounting or notify role)");
        None
    };

    // Confirmation watcher: PPLNS + Group-Solo block-founds park their frozen
    // distribution in Redis; this task applies it once the block reaches
    // `confirmation_depth` and discards it on orphan, so a reorg never drifts
    // the internal ledger. Accounting role only; without a TDP feed it runs on
    // the fallback timer alone. Blockparty is exempt: its fixed-percentage
    // payouts are recomputed from the DB, so there is nothing to drift.

    let block_confirmation = if is_accounting {
        let depth = cfg
            .pplns
            .as_ref()
            .map(|p| p.confirmation_depth)
            .unwrap_or(3);
        Some(crate::block_confirmation::spawn(
            handles.tdp.clone(),
            handles.bitcoin_rpc.clone(),
            handles.redis.clone(),
            engines.pplns.clone(),
            Some(engines.group_solo.clone()),
            depth,
            Some(settle_signal.clone()),
        ))
    } else {
        None
    };

    // Keep the PPLNS window's trim size on the CURRENT network difficulty.
    // Payout role only: the window is trimmed inside `record_share`, which
    // only that process runs. The source is the RPC because this process has
    // no TDP feed; see `crate::network_difficulty`.
    let _net_diff_refresh = match (cfg.has_role(Role::Payout), engines.pplns.as_ref()) {
        (true, Some(pplns)) => Some(crate::network_difficulty::spawn_refresh_task(
            handles.bitcoin_rpc.clone(),
            pplns.window().network_difficulty(),
            crate::network_difficulty::REFRESH_INTERVAL,
        )),
        // No PPLNS engine ⇒ no window to trim. Any other role never trims.
        _ => None,
    };

    // Periodic best-effort backup of the live PPLNS + Group-Solo Redis state
    // to Postgres, for a MANUAL restore after a Redis wipe
    // (`--restore-redis-state`). Payout process only, on its own Redis
    // connection so the SCAN/DUMP burst never touches the share hot-path.
    let _redis_state_backup = if cfg.has_role(Role::Payout) {
        let backup_redis = handles
            .dedicated_redis(&cfg.redis, "redis-state-backup")
            .await;
        Some(crate::redis_backup::spawn_backup_task(
            backup_redis,
            handles.db.pool().clone(),
            crate::redis_backup::DEFAULT_INTERVAL,
            crate::redis_backup::DEFAULT_RETENTION,
        ))
    } else {
        None
    };

    // Chain → ledger check: reads the coinbase of every block that landed and
    // reports the ones the ledger has no record of. Payout role, where that
    // ledger is written. Reports only: the chain does not carry the
    // distribution behind a coinbase, so it cannot book.
    let _block_reconcile = if cfg.has_role(Role::Payout) {
        let markers = crate::block_reconcile::PoolMarkers::new([
            cfg.pplns
                .as_ref()
                .map(|p| p.fee_address.clone())
                .unwrap_or_default(),
            cfg.solo.dev_fee_address.clone().unwrap_or_default(),
        ]);
        match markers {
            Some(markers) => Some(crate::block_reconcile::spawn_reconcile_task(
                handles.bitcoin_rpc.clone(),
                handles.db.pool().clone(),
                markers,
                engines.mode_gate.clone(),
                crate::block_reconcile::DEFAULT_INTERVAL,
                crate::block_reconcile::DEFAULT_LOOKBACK,
            )),
            None => {
                tracing::warn!(
                    "block-reconcile: SKIPPED — no pool fee address configured, so a coinbase \
                     carries no marker identifying it as this pool's. A block the ledger misses \
                     would go unnoticed."
                );
                None
            }
        }
    } else {
        None
    };

    // Satellite: drain the accepted-share stream the Core produces into the
    // real engine sinks (two consumer groups by durability class). Only the
    // back (accounting, no front role) consumes the stream.
    let satellite_consumer = if consumes_streams {
        let mut sinks = engines::build_accepted_sinks(
            engines.pplns.as_ref(),
            &engines.group_solo,
            &engines.stats,
            &engines.session_persistence,
            handles.redis.clone(),
        );
        // Blockparty auto-promote runs off the share-accept too — on the
        // satellite it joins the order-insensitive (aux) consumer group.
        if let Some(bp) = blockparty.as_ref() {
            sinks.aux.push(Arc::new(
                crate::blockparty_service::BlockpartyAcceptedShareSink::new(bp.service.clone()),
            ));
        }
        // Dedicated connection per consumer group — a blocking XREAD must not
        // share a multiplexed connection (it head-of-line-blocks the rest).
        let money_redis = handles.dedicated_redis(&cfg.redis, "satellite-money").await;
        let stats_redis = handles.dedicated_redis(&cfg.redis, "satellite-stats").await;
        Some(satellite_consumer::spawn(money_redis, stats_redis, sinks))
    } else {
        None
    };

    // Payout: drain the block-found stream for the engine ledger-write only (the
    // Core submits + records the durable blocks_entity row). No dispatcher:
    // the notify fan-out is a separate consumer on the `notify` role, so a
    // notification change never restarts payout.
    let block_found_consumer = if consumes_streams {
        let applier = crate::block_sink::BlockFoundApplier::new(
            engines.pplns.clone(),
            Some(engines.group_solo.clone()),
            engines.blockparty.clone(),
            None,
            Some(handles.redis.clone()),
            Some(settle_signal.clone()),
        );
        let bf_redis = handles
            .dedicated_redis(&cfg.redis, "block-found-ledger")
            .await;
        Some(crate::block_found_consumer::spawn(
            bf_redis,
            applier,
            crate::block_found_consumer::BlockFoundAction::Ledger,
        ))
    } else {
        None
    };

    // Notify: drain the block-found stream on its own consumer group and fan out
    // the notification only (no engines, no ledger). Runs alongside the payout
    // ledger consumer — both read every event independently.
    let block_found_notify_consumer = if consumes_notify_streams {
        match dispatcher.clone() {
            Some(d) => {
                let bf_notify_redis = handles
                    .dedicated_redis(&cfg.redis, "block-found-notify")
                    .await;
                let applier = crate::block_sink::BlockFoundApplier::new(
                    None,
                    None,
                    None,
                    Some(d),
                    None,
                    None,
                );
                Some(crate::block_found_consumer::spawn(
                    bf_notify_redis,
                    applier,
                    crate::block_found_consumer::BlockFoundAction::Notify,
                ))
            }
            None => None,
        }
    } else {
        None
    };

    // Satellite: drain the rejected-share stream into the Group-Solo + stats
    // reject counters (the Core stamps the group_id, then publishes).
    let rejected_consumer = if consumes_streams {
        let sinks = engines::build_rejected_sinks(&engines.group_solo, &engines.stats);
        let rej_redis = handles.dedicated_redis(&cfg.redis, "rejected").await;
        Some(crate::rejected_consumer::spawn(rej_redis, sinks))
    } else {
        None
    };

    // Notify: drain the device-status stream (miner online/offline events the
    // front publishes) and fan them out via the dispatcher. Only when a
    // dispatcher exists — with no transport configured there's nothing to send
    // and the stream just trims at MAXLEN.
    let device_status_consumer = if consumes_notify_streams {
        match device_status_gate.clone() {
            Some((g, subs)) => {
                let ds_redis = handles.dedicated_redis(&cfg.redis, "device-status").await;
                Some(crate::device_status_consumer::spawn(ds_redis, g, subs))
            }
            None => None,
        }
    } else {
        None
    };

    // The gate only sends from its sweeper, so a process holding the gate
    // must run one or debounced transitions are never released.
    let device_status_sweeper = match (device_status_gate.clone(), dispatcher.clone()) {
        (Some((g, subs)), Some(d)) => Some(crate::device_status_gate::spawn(
            g,
            subs,
            d,
            handles.db.pool().clone(),
        )),
        _ => None,
    };

    // Core: watch the Core→Satellite streams' consumer lag (the always-on
    // side notices the restartable Satellite falling behind / going down).
    // Budget = 10% of the default stream cap, so it fires well before MAXLEN
    // trims. Only the producing front runs it.
    let stream_monitor = if produces_streams {
        Some(crate::stream_monitor::spawn(
            handles.redis.clone(),
            vec![
                bp_share_stream::ACCEPTED_STREAM_KEY,
                bp_share_stream::REJECTED_STREAM_KEY,
                bp_share_stream::BLOCK_FOUND_STREAM_KEY,
                bp_share_stream::DEVICE_STATUS_STREAM_KEY,
            ],
            bp_share_stream::DEFAULT_STREAM_MAXLEN / 10,
        ))
    } else {
        None
    };

    // Latency diagnostics (front producer, gated by debug.submit_latency):
    // a runtime-stall watchdog + a Redis PING probe on the shared
    // ConnectionManager, to split a slow per-share XADD into "executor
    // starved" vs "ConnectionManager slow".
    let _runtime_diag = if produces_streams && cfg.debug.submit_latency {
        Some(crate::runtime_diag::spawn(handles.redis.clone()))
    } else {
        None
    };

    // Front: keep the Stratum routing caches (Group-Solo + Blockparty) in sync
    // with membership changes made on another process (the api). Drains the
    // `cache:invalidate` stream + rebuilds on a periodic backstop. Only the
    // Front routes shares, so only it needs this.
    let cache_sync = if is_front {
        // Dedicated Redis connection: the blocking `XREAD BLOCK 1000` would
        // head-of-line-stall every other command on a shared multiplexed
        // `ConnectionManager`, including the per-share `XADD`.
        let cache_conn = handles.dedicated_redis(&cfg.redis, "cache-sync").await;
        Some(crate::cache_sync::spawn(
            cache_conn,
            group_service.clone(),
            blockparty.as_ref().map(|bp| bp.service.clone()),
            engines.mode_gate.clone(),
            settle_signal.registry_slot(),
        ))
    } else {
        None
    };

    // One role-aware line stating this process's relationship to the Redis
    // streams. A process can consume the engine streams (accounting) and/or
    // the notify streams (notify).
    let any_consume = consumes_streams || consumes_notify_streams;
    match (produces_streams, any_consume) {
        (false, true) => tracing::info!(
            engine = consumes_streams,
            notify = consumes_notify_streams,
            "stream summary: consuming (accounting drains accepted/rejected/block-found-ledger; notify drains block-found-notify/device-status)"
        ),
        (true, false) => tracing::info!(
            "stream summary: producing (this core XADDs accepted/rejected/block-found/device-status)"
        ),
        // Neither produces nor consumes: a read-only api process (serves from
        // Postgres, never touches the streams).
        (false, false) => tracing::info!(
            "stream summary: no stream role (read-only process — serves from Postgres)"
        ),
        (true, true) => tracing::info!("stream summary: producing + consuming"),
    }

    // JDP + the coinbase-budget autoscaler are front-only and need the TDP
    // feed; without it (e.g. `--skip-tdp`) JDP binds nothing. `jdp` stays a
    // (disabled) handle either way so the shutdown sequence is uniform.
    //
    // The autoscaler tunes `coinbase_weight_budget` within [floor, ceiling]
    // against bitcoin-core's reservation; `None` unless
    // `[pplns.coinbase_autoscale]` is enabled.
    let (jdp, autoscaler) = if is_front {
        match handles.tdp.clone() {
            Some(tdp_handle) => {
                let autoscaler = coinbase_autoscaler::maybe_spawn(
                    cfg.pplns.as_ref(),
                    engines.pplns.as_ref(),
                    Some(&tdp_handle),
                    &handles.redis,
                )
                .await;
                // Fresh ProductionPayoutResolver for the JDP path; shares
                // `engines` + `cfg` with the one stratum.rs builds, so the two
                // always resolve the same answer for the same address.
                let jdp_payout_resolver =
                    std::sync::Arc::new(crate::payout_resolver::ProductionPayoutResolver::new(
                        engines.mode_gate.clone(),
                        engines.pplns.clone(),
                        engines.group_solo.clone(),
                        crate::payout_resolver::SoloFeeConfig {
                            dev_fee_address: cfg.solo.dev_fee_address.clone(),
                            dev_fee_percent: cfg.solo.dev_fee_percent.unwrap_or(0.0),
                        },
                        engines.blockparty.clone(),
                    ));
                // The JDP template-tx cache, when the pool needs the txs
                // (`jdp_orphan_submitblock` → reconstruct the full block +
                // `submitblock`). Spawned BEFORE jdp::spawn so its broadcast
                // subscription registers before the first NewTemplate.
                let template_tx_cache: Option<
                    std::sync::Arc<bp_template_distribution::TemplateTxCache>,
                > = if cfg.sv2.jdp_orphan_submitblock {
                    Some(std::sync::Arc::new(
                        bp_template_distribution::TemplateTxCache::spawn(&tdp_handle),
                    ))
                } else {
                    tracing::info!(
                        "jdp tx-cache: SKIPPED (sv2.jdp_orphan_submitblock = false); pool does \
                         not need declared tx-bytes — JDC propagates blocks via its own TDP \
                         submit_solution"
                    );
                    None
                };
                // Ledger fan-out for JDC-found blocks, built by the same
                // constructor as the Stratum sinks so a declared block books
                // through the same path a pool-built one does.
                let jdp_ledger_booker =
                    std::sync::Arc::new(crate::block_sink::TdpBlockSubmissionSink::wired(
                        tdp_handle.clone(),
                        &cfg,
                        &handles,
                        &engines,
                        dispatcher.clone(),
                        settle_signal.clone(),
                    ));
                let jdp = match jdp::spawn(
                    &cfg,
                    jdp_bridge,
                    tdp_handle,
                    handles.bitcoin_rpc.clone(),
                    jdp_payout_resolver,
                    template_tx_cache,
                    jdp_ledger_booker,
                    handles.redis.clone(),
                    settle_signal.clone(),
                )
                .await
                {
                    Ok(h) => h,
                    Err(err) => {
                        tracing::error!(%err, "jdp spawn failed");
                        eprintln!("blitzpool: {err}");
                        print_jdp_error_help(&err);
                        return ExitCode::from(9);
                    }
                };
                (jdp, autoscaler)
            }
            None => {
                tracing::warn!(
                    "jdp spawn: TDP not available (--skip-tdp); JDP listener will not bind."
                );
                (jdp::JdpHandles::disabled_for_init(), None)
            }
        }
    } else {
        (jdp::JdpHandles::disabled_for_init(), None)
    };
    log_jdp_summary(&jdp, is_front, cfg.sv2.jdp_enabled);

    tracing::info!(
        roles = ?cfg.effective_roles(),
        api = ?api.as_ref().map(|a| a.addr),
        stratum_ports = ?stratum.as_ref().map(|s| s.ports.clone()),
        jdp = ?jdp.port,
        "bound: process live. Send SIGTERM or Ctrl+C to shut down."
    );
    let engine_shutdown = EngineShutdownHandles {
        stats: engines.stats,
        pplns: engines.pplns,
        group_solo: engines.group_solo,
        session_persistence: engines.session_persistence,
    };
    wait_for_shutdown(
        api,
        stratum,
        jdp,
        crons,
        listeners,
        satellite_consumer,
        block_found_consumer,
        block_found_notify_consumer,
        rejected_consumer,
        device_status_consumer,
        device_status_sweeper,
        stream_monitor,
        cache_sync,
        autoscaler,
        block_confirmation,
        engine_shutdown,
    )
    .await;
    ExitCode::SUCCESS
}

/// Shutdown-relevant engine handles. `stats` consumes its handle for the
/// final drain; `session_persistence` drains its buffered touch updates.
struct EngineShutdownHandles {
    stats: bp_share_stats_sink::ShareStatsEngineHandle,
    pplns: Option<bp_pplns_engine::engine::PplnsEngine>,
    group_solo: bp_group_solo_engine::engine::GroupSoloEngine,
    session_persistence: bp_session_persistence::SessionPersistenceEngineHandle,
}

/// Block until a shutdown signal arrives or the API server task exits on its
/// own, then shut every subsystem down in order.
// One handle per subsystem; a struct would only move the list. Role-specific
// handles are `Option`, so a process shuts down only what it spawned.
#[allow(clippy::too_many_arguments)]
async fn wait_for_shutdown(
    api: Option<ApiServerHandle>,
    stratum: Option<StratumHandles>,
    jdp: JdpHandles,
    crons: Option<CronHandles>,
    listeners: ListenerHandles,
    satellite_consumer: Option<bp_share_stream::StreamConsumerHandle>,
    block_found_consumer: Option<bp_share_stream::StreamConsumerHandle>,
    block_found_notify_consumer: Option<bp_share_stream::StreamConsumerHandle>,
    rejected_consumer: Option<bp_share_stream::StreamConsumerHandle>,
    device_status_consumer: Option<bp_share_stream::StreamConsumerHandle>,
    device_status_sweeper: Option<crate::device_status_gate::DeviceStatusGateHandle>,
    stream_monitor: Option<stream_monitor::StreamMonitorHandle>,
    cache_sync: Option<cache_sync::CacheSyncHandle>,
    autoscaler: Option<coinbase_autoscaler::AutoscalerHandle>,
    block_confirmation: Option<block_confirmation::BlockConfirmationHandle>,
    engine_shutdown: EngineShutdownHandles,
) {
    use tokio::signal::unix::{signal, SignalKind};

    // Shutdown anchor: a signal, or the API task ending on its own. With no
    // API (a front-only process) the api arm is `pending()`, so only a signal
    // triggers shutdown.
    let api_join = async move {
        match api {
            Some(a) => {
                let res = a.join.await;
                tracing::warn!("api task ended before signal: {res:?}");
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(api_join);

    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => tracing::info!("ctrl-c received, shutting down"),
                _ = sigterm.recv() => tracing::info!("sigterm received, shutting down"),
                _ = &mut api_join => {}
            }
        }
        Err(err) => {
            tracing::warn!(%err, "couldn't install SIGTERM handler; falling back to Ctrl-C only");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => tracing::info!("ctrl-c received, shutting down"),
                _ = &mut api_join => {}
            }
        }
    }

    // Single shutdown sequence (both signal paths converge here). Cancel
    // engine-owned background tasks BEFORE the final drains so the next tick
    // doesn't fire mid-shutdown.
    if let Some(a) = autoscaler {
        a.shutdown().await;
    }
    if let Some(bc) = block_confirmation {
        bc.shutdown().await;
    }
    if let Some(sc) = satellite_consumer {
        sc.shutdown().await;
    }
    if let Some(bfc) = block_found_consumer {
        bfc.shutdown().await;
    }
    if let Some(bfnc) = block_found_notify_consumer {
        bfnc.shutdown().await;
    }
    if let Some(rc) = rejected_consumer {
        rc.shutdown().await;
    }
    if let Some(dsc) = device_status_consumer {
        dsc.shutdown().await;
    }
    if let Some(dsg) = device_status_sweeper {
        dsg.shutdown().await;
    }
    if let Some(sm) = stream_monitor {
        sm.shutdown().await;
    }
    if let Some(cs) = cache_sync {
        cs.shutdown().await;
    }
    if let Some(s) = stratum {
        s.shutdown().await;
    }
    jdp.shutdown().await;
    if let Some(c) = crons {
        c.shutdown().await;
    }
    if let Some(p) = engine_shutdown.pplns.as_ref() {
        p.shutdown();
    }
    engine_shutdown.group_solo.shutdown();
    // Final stats drain (consumes the handle by-value).
    engine_shutdown.stats.shutdown().await;
    listeners.shutdown().await;
    engine_shutdown.session_persistence.shutdown().await;
}

/// One-line-per-subsystem summary of what the config resolved to, before any
/// socket binds. Logs operational values (ports, hosts, toggles) and never
/// anything secret-shaped (passwords, tokens, keys).
fn log_startup_summary(cfg: &AppConfig) {
    tracing::info!(
        network = ?cfg.network,
        pool = %cfg.pool_identifier,
        "config loaded"
    );
    tracing::info!(
        host = %cfg.bitcoin_rpc.url,
        port = cfg.bitcoin_rpc.port,
        "bitcoin rpc target"
    );
    tracing::info!(
        host = %cfg.database.host,
        port = cfg.database.port,
        db = %cfg.database.database,
        pool_size = cfg.database.pool_size,
        "postgres target"
    );
    tracing::info!(
        host = %cfg.redis.host,
        port = cfg.redis.port,
        password_set = cfg.redis.password.is_some(),
        "redis target"
    );
    tracing::info!(
        api_port = cfg.api.port,
        solo = cfg.stratum.solo_port,
        solo_high_diff = cfg.stratum.solo_high_diff_port,
        "listener ports"
    );
    if let Some(pplns) = &cfg.pplns {
        tracing::info!(
            port = pplns.port,
            high_diff_port = pplns.high_diff_port,
            fee_percent = pplns.fee_percent,
            min_payout_sats = pplns.min_payout_sats,
            "pplns mode enabled"
        );
    } else {
        tracing::info!("pplns mode disabled (no [pplns] table in config)");
    }
    if cfg.sv2.jdp_enabled {
        tracing::info!(
            jdp_port = ?cfg.sv2.jdp_port,
            authority_key_set = cfg.sv2.authority_privkey_hex.is_some(),
            "sv2 jdp enabled"
        );
    }
    tracing::info!(
        smtp_configured = cfg.smtp.is_some(),
        telegram_configured = cfg.notifications.telegram.is_some(),
        ntfy_configured = cfg.notifications.ntfy.is_some(),
        web_push_configured = cfg.notifications.web_push.is_some(),
        fcm_configured = cfg.notifications.fcm.is_some(),
        "outbound channels"
    );
}

/// One-line summary after the bp-api HTTP listener is bound, or why it is not
/// run on this process.
fn log_api_summary(api: Option<&ApiServerHandle>, is_api: bool) {
    match api {
        Some(a) => tracing::info!(addr = %a.addr, "bp-api summary: listening"),
        None if !is_api => {
            tracing::info!("bp-api summary: not run on this process (no api role)")
        }
        None => tracing::info!("bp-api summary: not bound"),
    }
}

/// One-line summary after the unified SV1+SV2 listeners are bound, or why
/// none are. Empty `ports` on the front means TDP was skipped
/// (`--skip-tdp`): listeners without templates would reject every connection.
fn log_stratum_summary(stratum: Option<&StratumHandles>, is_front: bool) {
    match stratum {
        Some(h) if h.ports.is_empty() => {
            tracing::info!("stratum summary: no listeners bound (TDP skipped)")
        }
        Some(h) => {
            tracing::info!(ports = ?h.ports, "stratum summary: listening (SV1+SV2 multiplexed per port)")
        }
        None if !is_front => {
            tracing::info!("stratum summary: not run on this process (no front role)")
        }
        None => tracing::info!("stratum summary: not bound"),
    }
}

/// One-line summary after JDP spawn returns. Off the front it says *why*
/// (wrong role), since a bare "disabled" reads like a misconfiguration when
/// `jdp_enabled = true`.
fn log_jdp_summary(handles: &JdpHandles, is_front: bool, jdp_enabled: bool) {
    match handles.port {
        Some(p) => tracing::info!(port = p, "jdp summary: listening"),
        None if !is_front => tracing::info!(
            "jdp summary: not run on this process (JDP is front-only; it binds on the core)"
        ),
        None if !jdp_enabled => {
            tracing::info!("jdp summary: disabled (sv2.jdp_enabled = false)")
        }
        None => {
            tracing::info!("jdp summary: enabled but not bound (TDP unavailable on this process)")
        }
    }
}

/// Operator-friendly hint for [`StratumSpawnError`] variants.
fn print_stratum_error_help(err: &StratumSpawnError) {
    match err {
        StratumSpawnError::Bind { addr, .. } => {
            eprintln!(
                "hint: couldn't bind {addr} — port {} probably in use. \
                 Check `[stratum]` + `[pplns]` port settings against \
                 `ss -tlnp` / `lsof -i :{}`.",
                addr.port(),
                addr.port(),
            );
        }
        StratumSpawnError::Sv1(stratum_v1::StratumV1SpawnError::PortConfig { port, .. }) => {
            eprintln!(
                "hint: port {port} SV1 config rejected. Most common cause: \
                 a difficulty / target-shares value that's zero or non-finite. \
                 Re-check the corresponding `[stratum]` / `[pplns]` field."
            );
        }
        StratumSpawnError::Sv1(stratum_v1::StratumV1SpawnError::ServerConfig(_)) => {
            eprintln!(
                "hint: the server-wide SV1 config failed validation. \
                 Check `[solo] dev_fee_address` + `dev_fee_percent` \
                 (percent must be in [0, 100]; address must be \
                 non-empty when set)."
            );
        }
        StratumSpawnError::Sv2(stratum_v2::StratumV2SpawnError::PrivkeyMissing) => {
            eprintln!(
                "hint: SV2 needs `[sv2] authority_privkey_hex` (32-byte \
                 secp256k1 secret key, hex-encoded). Generate one with \
                 `openssl rand -hex 32`."
            );
        }
        StratumSpawnError::Sv2(_) => {
            eprintln!(
                "hint: SV2 noise config init failed — verify \
                 `[sv2].authority_privkey_hex` is exactly 64 hex chars \
                 (32 raw bytes) and a valid secp256k1 scalar (1..n-1)."
            );
        }
    }
}

/// Operator-friendly hint for [`ListenerSpawnError`] variants.
fn print_listener_error_help(err: &ListenerSpawnError) {
    match err {
        ListenerSpawnError::Telegram(_) => {
            eprintln!(
                "hint: `[notifications.telegram]` is set but the bot token is \
                 empty or rejected. Check that `bot_token` points at a valid \
                 @BotFather-issued token."
            );
        }
        ListenerSpawnError::Ntfy(_) => {
            eprintln!(
                "hint: `[notifications.ntfy]` is set but the adapter rejected the \
                 config — `server_url` empty? Self-hosted instance unreachable?"
            );
        }
    }
}

/// Operator-friendly hint for [`JdpSpawnError`] variants.
fn print_jdp_error_help(err: &JdpSpawnError) {
    match err {
        JdpSpawnError::PortMissing => {
            eprintln!(
                "hint: `[sv2] jdp_enabled = true` but `jdp_port` is unset. \
                 Either set the port (default: 3335) or set \
                 `jdp_enabled = false`."
            );
        }
        JdpSpawnError::Bind { addr, .. } => {
            eprintln!(
                "hint: couldn't bind JDP listener on {addr} — port {} \
                 already in use? Check with `ss -tlnp`.",
                addr.port(),
            );
        }
        JdpSpawnError::ValidationSocket(detail) => {
            eprintln!(
                "hint: `[sv2] jdp_validation_socket_path` — {detail}\n\
                 It is normally the SAME socket as `[tdp] socket_path`, since \
                 declared-job validation is a second interface on the one node. \
                 Unset it to keep running without validation."
            );
        }
        JdpSpawnError::Sv2(_) => {
            eprintln!(
                "hint: JDP needs the same `[sv2].authority_privkey_hex` \
                 the mining-server uses (shared Noise authority)."
            );
        }
    }
}

/// Operator-friendly hint for [`ApiServerError`] variants.
fn print_api_error_help(err: &ApiServerError) {
    match err {
        ApiServerError::Bind { addr, .. } => {
            eprintln!(
                "hint: couldn't bind {addr} — port {} probably in use. \
                 Check `[api] port` against `ss -tlnp` / `lsof -i :{}` to \
                 find the conflicting process.",
                addr.port(),
                addr.port(),
            );
        }
    }
}

/// One-line-per-hook summary after [`hooks::spawn`] returns.
fn log_hooks_summary(_h: &ProductionHooks) {
    // The aggregate is `Arc<dyn _>`-typed, so the concrete impls are not
    // visible here; `hooks::spawn` logs their readiness. This line anchors
    // the phase boundary.
    tracing::info!(
        email_verification_ready = true,
        invitation_email_ready = true,
        push_ready = true,
        group_service_ready = true,
        "production hooks summary"
    );
}

/// Operator-friendly hint for [`GroupServiceSpawnError`] variants.
fn print_group_service_error_help(err: &GroupServiceSpawnError) {
    match err {
        GroupServiceSpawnError::Rebuild(_) => {
            eprintln!(
                "hint: the initial address-cache rebuild hit PG — check \
                 that the `pplns_group` + `pplns_group_member` tables are \
                 present in the configured database. If you migrated from \
                 a prior schema make sure both tables made it across."
            );
        }
    }
}

/// Operator-friendly hint for [`HooksError`] variants.
fn print_hooks_error_help(err: &HooksError) {
    match err {
        HooksError::Smtp(_) => {
            eprintln!(
                "hint: SMTP adapter init rejected `[smtp]` — check `host` is \
                 a deliverable mailserver hostname, `from` is an RFC 5322 \
                 mailbox like \"Display <addr@example.com>\", and `secure` \
                 matches the port (true ⇒ 465, false ⇒ STARTTLS / 587)."
            );
        }
        HooksError::Fcm(_) | HooksError::FcmIo { .. } => {
            eprintln!(
                "hint: FCM init couldn't load the service-account JSON at \
                 `[notifications.fcm] service_account_path`. The file must \
                 be a Firebase Admin SDK service-account JSON the process \
                 can read."
            );
        }
        HooksError::WebPush(_) => {
            eprintln!(
                "hint: Web-Push adapter rejected the VAPID config — \
                 `[notifications.web_push] vapid_private_key` must be an \
                 ECDSA P-256 private key in PEM form (PKCS#8 or SEC1)."
            );
        }
    }
}

/// One-line-per-engine summary after [`engines::spawn`] returns.
fn log_engines_summary(e: &EngineHandles) {
    tracing::info!(
        pplns = e.pplns.is_some(),
        group_solo_ready = true,
        stats_ready = true,
        session_persistence_ready = true,
        "engine handles summary"
    );
}

/// Operator-friendly hint for [`EngineError`] variants — each maps
/// to a distinct config-or-runtime symptom.
fn print_engine_error_help(err: &EngineError) {
    match err {
        EngineError::Pplns(_) | EngineError::PplnsConfig(_) => {
            eprintln!(
                "hint: check `[pplns]` fields — `fee_address` must be a \
                 valid bitcoin address for the configured `network`, \
                 `fee_percent` ∈ [0.0, 100.0], `min_payout_sats` ≥ 546."
            );
        }
        EngineError::GroupSolo(_) | EngineError::GroupSoloConfig(_) => {
            eprintln!(
                "hint: check `[solo]` fields. Group-Solo reuses the solo \
                 `dev_fee_*` knobs. `min_payout_sats` is shared with PPLNS \
                 — both must satisfy ≥ 546 (Bitcoin Core relay dust limit)."
            );
        }
        EngineError::Stats(_) => {
            eprintln!(
                "hint: the share-stats engine couldn't bootstrap. Likely \
                 cause: the `seed_if_empty` migration hit a PG row-level \
                 constraint. Inspect the DB tracing output above the \
                 error line for the failing query."
            );
        }
        EngineError::SessionPersistence(_) => {
            eprintln!(
                "hint: session-persistence config rejected — the flush/sample \
                 intervals must be > 0."
            );
        }
        EngineError::InvalidAddress(_, _) => {
            eprintln!(
                "hint: a configured bitcoin address didn't parse against \
                 the active `network`. Confirm prefix matches mainnet vs \
                 testnet vs regtest in your config."
            );
        }
        EngineError::CoreEpoch(_) => {
            eprintln!(
                "hint: failed to fetch the share-id epoch (`INCR core:epoch`) \
                 from Redis at engine spawn. Redis must be reachable here — \
                 check the `[redis]` URL and that the server is up."
            );
        }
    }
}

/// One-line-per-handle summary after [`boot::boot`] returns: the live-handle
/// counterpart of [`log_startup_summary`].
fn log_handles_summary(h: &FoundationHandles) {
    // db/redis/bitcoin_rpc are live here, since boot::boot returns Err if any
    // fails. `tdp` is optional (front-only, and absent under --skip-tdp).
    tracing::info!(
        db_ready = true,
        redis_ready = true,
        bitcoin_rpc_ready = true,
        tdp_ready = h.tdp.is_some(),
        geoip = h.geoip.is_some(),
        metrics = h.metrics.is_some(),
        "foundation handles summary"
    );
}

/// Operator-friendly hint when boot fails. Each [`BootError`]
/// variant has a distinct + actionable suggestion.
fn print_boot_error_help(err: &BootError) {
    match err {
        BootError::Db(_) => {
            eprintln!(
                "hint: check `[database]` host/port/credentials in your config + \
                 that the Postgres container is reachable from this process \
                 (network firewall / docker network)."
            );
        }
        BootError::Redis(_) => {
            eprintln!(
                "hint: check `[redis]` host/port/password in your config + \
                 that the Redis container is reachable. The pool is \
                 Redis-essential — share-stats + PPLNS state both live there."
            );
        }
        BootError::BitcoinRpc(_) => {
            eprintln!(
                "hint: check `[bitcoin_rpc]` URL + credentials + that the \
                 bitcoind RPC port (default 8332 mainnet) is reachable."
            );
        }
        BootError::BitcoinRpcLiveness(_) => {
            eprintln!(
                "hint: bitcoind responded at the network layer but rejected \
                 the `getnetworkinfo` call — verify `[bitcoin_rpc] user/password` \
                 against `bitcoin.conf` rpcauth, and that the node is fully \
                 started (not in IBD)."
            );
        }
        BootError::Tdp(_) => {
            eprintln!(
                "hint: `[tdp] socket_path` must point at the bitcoin-core IPC \
                 socket. Per memory `project-tdp-direct-architecture` the Rust \
                 port uses TDP-direkt — bitcoind must be built with the IPC \
                 bridge + the socket file present + readable by this process."
            );
        }
    }
}

/// Operator-friendly hint when the config can't be loaded. Most of
/// the failure modes are "file not found" or "deny_unknown_fields"
/// tripping on a typo — both have actionable next steps.
fn print_config_error_help(err: &ConfigError) {
    match err {
        ConfigError::Io { path, .. } => {
            eprintln!(
                "hint: pass --config <PATH> to point at a different file. \
                 The repo ships a template at `blitzpool.example.toml` — \
                 copy that to `.local/blitzpool.toml` and edit it."
            );
            let _ = path;
        }
        ConfigError::Parse { .. } => {
            eprintln!(
                "hint: unknown-field errors come from a typo in the TOML \
                 key. Compare your file against `blitzpool.example.toml`."
            );
        }
    }
}

/// Standard tracing setup: `RUST_LOG` env-filter (default `info`),
/// line-oriented formatter to stdout.
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}
