// SPDX-License-Identifier: AGPL-3.0-or-later

// The workspace clippy lints deny `print_stderr` / `print_stdout` to
// keep library code from sneaking diagnostics around `tracing`. The
// binary is the legitimate exception: operator-facing startup errors
// + actionable hints go to stderr alongside the tracing line so the
// operator sees them even with a stricter `RUST_LOG` filter.
#![allow(clippy::print_stderr)]

//! `blitzpool` binary entry-point.
//!
//! Phase 7.3 scope: extends the 7.2 engine spawn with production
//! hook impls. Order of operations: load `AppConfig` (7.0) → spawn
//! foundation handles via [`boot::boot`] (7.1) → spawn engines via
//! [`engines::spawn`] (7.2) → spawn production hooks via
//! [`hooks::spawn`] (7.3). After hooks are live the binary exits —
//! the actual `run(cfg, handles, engines, hooks)` loop lands in
//! Phase 7.4 alongside Stratum binding.
//!
//! Phase plan: 7.4 (Stratum servers + BlockSubmissionSink wiring),
//! 7.5 (cron wiring), 7.6 (listeners), 7.7 (NotificationDispatcher
//! engine hookup), 7.8 (metric instrumentation sweep), 7.9
//! (cut-over staging on `172.16.0.21`).
//!
//! The single user-facing knob is `--config <PATH>` (default
//! `./blitzpool.toml`). On a Phase-7-staging machine the operator
//! typically points it at `.local/blitzpool.toml`.

// Process-wide allocator. jemalloc bounds RSS under the pool's
// small-alloc / free pattern (per-connection Stratum buffers +
// sqlx / redis query results across 600+ concurrent clients).
// glibc malloc fragments under sustained load, so we adopt jemalloc
// preemptively rather than re-discover the problem in production.
// Linux only — tikv-jemallocator doesn't support Windows MSVC.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod api_server;
mod block_confirmation;
mod block_found_consumer;
mod block_sink;
mod blockparty_reservation;
mod blockparty_service;
mod boot;
mod cache_sync;
mod coinbase_autoscaler;
mod crons;
mod device_status;
mod device_status_consumer;
mod dispatcher;
mod engines;
mod group_service;
mod hooks;
mod jdp;
mod jdp_hooks;
mod listeners;
mod live_mode_marker;
mod payout_resolver;
mod pending_blocks;
mod pending_group_solo_blocks;
mod pending_store;
mod rejected_consumer;
mod runtime_diag;
mod satellite_consumer;
mod stratum;
mod stratum_v1;
mod stratum_v2;
mod stream_monitor;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use bp_config::{AppConfig, ConfigError, Role};
use bp_pplns::DEFAULT_COINBASE_WEIGHT_BUDGET;
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

/// CLI surface — kept deliberately small in 7.0. Additions in later
/// sub-phases (e.g. `--migrate-only`, `--dry-run`) extend this
/// struct; the operator-visible flags grow with the bin's scope.
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
    /// BitcoinRpc, TDP, GeoIP, Metrics), then exit cleanly. Used to
    /// validate a deployment can actually reach its external
    /// dependencies before flipping the production-traffic switch.
    /// `--check-config` short-circuits this — pass `--check-boot`
    /// without `--check-config` to actually try connecting.
    #[arg(long)]
    check_boot: bool,

    /// Like `--check-boot` but extends through engine spawning
    /// (PPLNS / Group-Solo / ShareStats / SessionPersistence). The
    /// background tasks each engine spawns are torn down via the
    /// process exit. Use to verify a deployment can construct the
    /// service layer on top of its foundation.
    #[arg(long)]
    check_engines: bool,

    /// Like `--check-engines` but extends through production hook
    /// construction (SMTP / FCM / Web-Push adapter init,
    /// GroupServiceHooks wiring). Validates that all configured
    /// `[smtp]` / `[notifications.*]` blocks parse + that any
    /// referenced files (FCM service-account JSON, VAPID PEM) load
    /// without error before flipping a deployment live.
    #[arg(long)]
    check_hooks: bool,

    /// Like `--check-hooks` but extends through binding the bp-api
    /// HTTP listener on `[api] port`. Exits as soon as the listener
    /// is up — useful for verifying the port isn't already in use.
    #[arg(long)]
    check_api: bool,

    /// Like `--check-api` but extends through binding the unified
    /// SV1+SV2 Stratum listeners (solo + solo-high-diff + optionally
    /// pplns + pplns-high-diff). Exits cleanly once all listeners
    /// are up. Each port multiplexes SV1 + SV2 via
    /// [`bp_protocol_detect`]; JDP runs on its own `[sv2].jdp_port`
    /// and is verified together with the stratum stack.
    #[arg(long)]
    check_stratum: bool,

    /// Skip the bitcoin-rpc `getnetworkinfo` liveness ping during
    /// boot. The RPC client still gets built but its reachability /
    /// auth aren't verified. Production should never set this; the
    /// flag exists so staging boxes can validate the rest of the
    /// stack (PG / Redis / HTTP) before the bitcoin node is online.
    #[arg(long)]
    skip_bitcoin_rpc_liveness: bool,

    /// Skip the TDP worker spawn entirely. Useful when bitcoind isn't
    /// running locally but we still want to verify the api / engines
    /// layer. PPLNS network-difficulty bootstrap falls back to 1.0.
    #[arg(long)]
    skip_tdp: bool,

    /// Override the config's deployment roles (comma-separated:
    /// `front,api,payout,stats,notify`). When set, takes precedence over the
    /// `roles` list in the config — so every container can mount the same
    /// config and differ only by `--roles` or the `BLITZPOOL_ROLES` env var.
    #[arg(long, env = "BLITZPOOL_ROLES", value_delimiter = ',')]
    roles: Vec<Role>,
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
            // Plain stderr too: tracing's formatter may suppress
            // colourised output under non-TTY conditions and the
            // operator still wants the path.
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

    // Boot-time role validation — after the config-parse check, since roles
    // commonly arrive via BLITZPOOL_ROLES at deploy time rather than the
    // config file (so `--check-config` validates parsing without requiring them).
    //
    // Roles are the only topology input — a process with no role can't do
    // anything useful. Require one (config `roles` or BLITZPOOL_ROLES) and fail
    // fast with a pointed message rather than booting an inert process.
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
    // payout Satellite consumes them. A single process holding both `front`
    // and `payout` would produce shares no one consumes — fail fast rather
    // than silently drop the money path. Run the front (core) and the payout
    // back (satellite) as separate processes (see full-setup/DEPLOYMENT.md).
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
    // Loud, not silent: an accounting process without the notify role means the
    // notifications live in a separate `notify` process — warn so an operator
    // who forgot to run one notices immediately (rather than wondering why no
    // pushes fire).
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

    // Phase 7.7: build NotificationDispatcher from the four adapter
    // singletons (FCM + Web-Push from hooks; Telegram + ntfy from
    // listeners). `None` when no transport is wired — the block-found
    // sink and best-diff cron then collapse their `notify_*` calls
    // into no-ops rather than building pointless event payloads.
    //
    // Notify-only: the dispatcher's drivers (best-diff/hourly/network crons,
    // the block-found notify consumer, and the device-status consumer) all live
    // where `notify` runs. Off the notify role it is `None`, so a front produces
    // the block-found + device-status events to streams instead, for the notify
    // process to fan out.
    let dispatcher = if is_notify {
        dispatcher::build(&handles, &production_hooks, &listeners)
    } else {
        None
    };

    let group_service = match group_service::spawn(&handles, &production_hooks).await {
        Ok(g) => g,
        Err(err) => {
            tracing::error!(%err, "group-service spawn failed");
            eprintln!("blitzpool: {err}");
            print_group_service_error_help(&err);
            return ExitCode::from(7);
        }
    };

    let blockparty =
        match blockparty_service::spawn(&cfg, &handles, &group_service, &production_hooks).await {
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
        // Bidirectional mode-collision: PPLNS-group adds now refuse
        // addresses already in a Blockparty.
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

    // Stratum listeners + share producer are the always-on front — front-only.
    let stratum = if is_front {
        match stratum::spawn(&cfg, &handles, &engines, &group_service, dispatcher.clone()).await {
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
    // invitation/join expiry, capacity alert) on the accounting role; the
    // notification crons (network-difficulty, best-difficulty, hourly stats) on
    // the notify role. The best_difficulty + hourly crons additionally need
    // their fan-out (`dispatcher` / listeners) wired, and seed from
    // address_settings to avoid cold-start notification spam. A process running
    // both roles spawns both groups.
    let crons = if is_accounting || is_notify {
        let cap_params = crons::CapacityMonitorParams {
            pplns_window: engines.pplns.as_ref().map(|e| e.window().clone()),
            coinbase_budget: engines
                .pplns
                .as_ref()
                .map(|e| e.coinbase_budget().get())
                .unwrap_or(DEFAULT_COINBASE_WEIGHT_BUDGET),
            has_fee_output: engines
                .pplns
                .as_ref()
                .map(|e| e.config().fee_address.is_some())
                .unwrap_or(false),
        };
        let crons = crons::spawn(
            &handles,
            &production_hooks,
            &listeners,
            dispatcher.clone(),
            cap_params,
            &cfg.capacity_alert,
            cfg.pool_admin_email.as_deref(),
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

    // Confirmation watcher: PPLNS + Group-Solo block-founds freeze their
    // distribution and park it (Redis) instead of writing the ledger
    // immediately; this task applies it once the block reaches
    // `confirmation_depth` and discards it on orphan / non-chain-extending
    // candidate, so a reorg never drifts the internal ledger. It is accounting
    // → back-only, and runs whenever there's an engine to reconcile. The TDP
    // feed (a fast new-tip trigger) is optional: the Satellite has none and runs
    // on the fallback timer alone. (Blockparty is exempt — fixed-percentage
    // payouts recomputed from the DB, idempotent, nothing to drift.)
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
        ))
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
        let money_redis = dedicated_redis(&cfg.redis, &handles.redis, "satellite-money").await;
        let stats_redis = dedicated_redis(&cfg.redis, &handles.redis, "satellite-stats").await;
        Some(satellite_consumer::spawn(money_redis, stats_redis, sinks))
    } else {
        None
    };

    // Payout: drain the block-found stream for the engine ledger-write only (the
    // Core submits + records the durable blocks_entity row). Dispatcher is
    // `None` here by construction — the notify fan-out is a separate consumer on
    // the `notify` role (below), so a notification change never restarts payout.
    let block_found_consumer = if consumes_streams {
        let applier = crate::block_sink::BlockFoundApplier::new(
            engines.pplns.clone(),
            Some(engines.group_solo.clone()),
            engines.blockparty.clone(),
            None,
            Some(handles.redis.clone()),
        );
        let bf_redis = dedicated_redis(&cfg.redis, &handles.redis, "block-found-ledger").await;
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
                let bf_notify_redis =
                    dedicated_redis(&cfg.redis, &handles.redis, "block-found-notify").await;
                let applier =
                    crate::block_sink::BlockFoundApplier::new(None, None, None, Some(d), None);
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
        let rej_redis = dedicated_redis(&cfg.redis, &handles.redis, "rejected").await;
        Some(crate::rejected_consumer::spawn(rej_redis, sinks))
    } else {
        None
    };

    // Notify: drain the device-status stream (miner online/offline events the
    // front publishes) and fan them out via the dispatcher. Only when a
    // dispatcher exists — with no transport configured there's nothing to send
    // and the stream just trims at MAXLEN.
    let device_status_consumer = if consumes_notify_streams {
        match dispatcher.clone() {
            Some(d) => {
                let ds_redis = dedicated_redis(&cfg.redis, &handles.redis, "device-status").await;
                Some(crate::device_status_consumer::spawn(ds_redis, d))
            }
            None => None,
        }
    } else {
        None
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
    // starved" vs "ConnectionManager slow". Tasks run for the process
    // lifetime; the binding only makes ownership explicit.
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
        // Dedicated Redis connection. cache-sync does a blocking
        // `XREAD BLOCK 1000` for cache invalidations; on a *shared*
        // multiplexed `ConnectionManager` that 1s block head-of-line-stalls
        // every other command on the same connection — including the
        // per-share accepted-share `XADD` — which surfaces as multi-hundred-
        // ms share-ack spikes. A blocking command MUST get its own
        // connection. Fall back to the shared handle only if a fresh
        // connection can't be opened.
        let cache_conn = dedicated_redis(&cfg.redis, &handles.redis, "cache-sync").await;
        Some(crate::cache_sync::spawn(
            cache_conn,
            group_service.clone(),
            blockparty.as_ref().map(|bp| bp.service.clone()),
        ))
    } else {
        None
    };

    // One role-aware line for the Core→Satellite stream topology so an operator
    // reading any container's log knows its relationship to the Redis streams
    // without grepping for each consumer's `: live`. A process can consume the
    // engine streams (accounting) and/or the notify streams (notify).
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

    // JDP + the coinbase-budget autoscaler are front-only (mining / block
    // submit + coinbase-budget tuning). Both need the TDP feed; without it
    // (e.g. `--skip-tdp`) JDP binds nothing and the autoscaler can't couple
    // to bitcoin-core. `jdp` stays a (disabled) handle either way so the
    // shutdown sequence is uniform.
    //
    // The JDP bridge is spawned fresh here — real shared-bridge cross-routing
    // between JDP-declared jobs and the SV2 mining-server `SetCustomMiningJob`
    // happens once an actual JDC is in the loop; the topology supports it via
    // a single `Arc` clone. The autoscaler self-tunes `coinbase_weight_budget`
    // within [floor, ceiling], coupling the trimmer budget to bitcoin-core's
    // reservation; `None` unless `[pplns.coinbase_autoscale]` is enabled.
    let (jdp, autoscaler) = if is_front {
        let jdp_bridge = stratum_v2::build_bridge();
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
                // Spawn the JDP template-tx cache only when the pool needs the
                // txs (`jdp_orphan_submitblock = true` → reconstruct the full
                // block + `submitblock`). Spawn it BEFORE jdp::spawn so its
                // broadcast subscription registers before the first NewTemplate
                // (see `feedback-tdp-initial-template-drain`).
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
                let jdp = match jdp::spawn(
                    &cfg,
                    jdp_bridge,
                    tdp_handle,
                    handles.bitcoin_rpc.clone(),
                    jdp_payout_resolver,
                    template_tx_cache,
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
        stream_monitor,
        cache_sync,
        autoscaler,
        block_confirmation,
        engine_shutdown,
    )
    .await;
    ExitCode::SUCCESS
}

/// Block until a shutdown signal arrives or the API server task
/// exits on its own. On signal we shut down stratum + JDP cleanly,
/// then drop the api task — axum's serve loop exits cleanly when the
/// listener is dropped.
/// Shutdown-relevant engine handles, bundled so the shutdown sequence stays
/// explicit. `stats` consumes its handle (final drain on `shutdown(mut self)`);
/// `pplns` + `group_solo` are clone-able and signal via `cancel_tx`;
/// `session_persistence` drains its buffered touch updates.
struct EngineShutdownHandles {
    stats: bp_share_stats_sink::ShareStatsEngineHandle,
    pplns: Option<bp_pplns_engine::engine::PplnsEngine>,
    group_solo: bp_group_solo_engine::engine::GroupSoloEngine,
    session_persistence: bp_session_persistence::SessionPersistenceEngineHandle,
}

// Shutdown orchestration legitimately threads one handle per subsystem;
// bundling them into a struct would just move the list, not shorten it.
// Front-/back-only handles are `Option` — a process shuts down only what it
// actually spawned.
#[allow(clippy::too_many_arguments)]
async fn wait_for_shutdown(
    api: Option<ApiServerHandle>,
    stratum: Option<StratumHandles>,
    jdp: JdpHandles,
    crons: Option<CronHandles>,
    listeners: ListenerHandles,
    satellite_consumer: Option<satellite_consumer::SatelliteConsumerHandle>,
    block_found_consumer: Option<block_found_consumer::BlockFoundConsumerHandle>,
    block_found_notify_consumer: Option<block_found_consumer::BlockFoundConsumerHandle>,
    rejected_consumer: Option<rejected_consumer::RejectedConsumerHandle>,
    device_status_consumer: Option<device_status_consumer::DeviceStatusConsumerHandle>,
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

/// One-line-per-subsystem summary so an operator can sanity-check
/// what the config file resolved to before any sockets bind in
/// Phase 7.1+. We deliberately log values that are operationally
/// useful (ports, hostnames, feature toggles) and explicitly redact
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

/// One-line summary after the bp-api HTTP listener is bound. The API is a
/// back-office surface (`api` role), so on the front it's not run — say so
/// rather than logging nothing.
fn log_api_summary(api: Option<&ApiServerHandle>, is_api: bool) {
    match api {
        Some(a) => tracing::info!(addr = %a.addr, "bp-api summary: listening"),
        None if !is_api => {
            tracing::info!("bp-api summary: not run on this process (no api role)")
        }
        None => tracing::info!("bp-api summary: not bound"),
    }
}

/// One-line summary after the unified SV1+SV2 listeners are bound. Stratum is
/// A dedicated Redis [`ConnectionManager`](redis::aio::ConnectionManager) for
/// a blocking stream consumer. A blocking command (`XREAD BLOCK`) must never
/// share a multiplexed connection — it head-of-line-blocks every command
/// queued behind it on that one connection. Falls back to the shared handle
/// only if a fresh connection can't be opened.
async fn dedicated_redis(
    cfg: &bp_config::RedisConfig,
    shared: &redis::aio::ConnectionManager,
    who: &str,
) -> redis::aio::ConnectionManager {
    match crate::boot::spawn_redis(cfg).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                consumer = who,
                "dedicated redis connection failed; reusing the shared handle \
                 (its blocking read may stall this process's redis throughput)"
            );
            shared.clone()
        }
    }
}

/// the always-on front (`front` role), so on the api/payout processes it's not
/// run — say so rather than logging nothing. Empty `ports` on the front means
/// TDP was skipped (`--skip-tdp`) — stratum spawn is a no-op in that case to
/// avoid binding listeners that would reject every connection.
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

/// One-line summary after JDP spawn returns. JDP is front-only, so on the
/// `api`/`payout` processes it's never bound — say *why* (wrong role) rather
/// than a bare "disabled", which reads like a misconfiguration when the
/// operator did set `jdp_enabled = true`.
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
        StratumSpawnError::Sv2(stratum_v2::StratumV2SpawnError::AuthorityKeyMissing) => {
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
    // The aggregate is Arc<dyn _>-typed so we can't introspect
    // which concrete impl landed. The boot path already logs
    // `smtp_ready` / `fcm_ready` / `web_push_ready` from inside
    // `hooks::spawn`; this line just anchors the phase boundary.
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
                "hint: session-persistence config rejected — check the \
                 `address_cache_capacity` knob (must be > 0)."
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

/// One-line-per-handle summary after [`boot::boot`] returns. Mirrors
/// [`log_startup_summary`] but for the live handles — gives the
/// operator a single grep-friendly anchor for "did the foundation
/// come up cleanly?".
fn log_handles_summary(h: &FoundationHandles) {
    // db/redis/bitcoin_rpc are non-optional — boot::boot returns Err if any
    // fail, so reaching here means they're live. `tdp` is optional (front-only;
    // skipped on api/payout and under --skip-tdp), so report its real state
    // rather than a hardcoded `true` that misleads on the satellites.
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

/// Standard tracing setup — `RUST_LOG` env-filter, line-oriented
/// formatter to stdout. The `EnvFilter::try_from_default_env()` call
/// falls back to the supplied default when `RUST_LOG` isn't set,
/// matching the convention used by every other Rust binary in the
/// ecosystem (tracing's own docs, axum examples, sqlx-cli, etc.).
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}
