// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notifications crate for blitzpool-rust.
//!
//! Five layers:
//!
//! - [`template`] — pure email-template rendering (`subject`/`html`/`text`).
//! - [`adapter`] — outbound transports (SMTP, Telegram, ntfy, FCM, Web-Push).
//! - [`dispatcher`] — fan-out orchestrator that turns engine events
//!   (`block_found`, `best_diff`, `device_status`) into per-subscriber
//!   adapter calls, looking subscriptions up in `bp-db`.
//! - [`command`] — bot-command parsing + dispatch (`/subscribe`,
//!   `/show_addresses`, `/deutsch`, …); shared between Telegram + ntfy.
//! - [`listener`] — long-running inbound loops (Telegram long-poll,
//!   ntfy SSE) that turn upstream traffic into `command::dispatch` calls.
//! - [`cron`] — periodic self-checks (network-difficulty poller,
//!   best-difficulty cron) that emit events through the dispatcher.
//!
//! Read-style commands (`/stats`, `/show_workers`, `/pplns_status`,
//! `/group_status`, etc.) need engine-reader wiring and are deferred.

pub mod adapter;
pub mod command;
pub mod cron;
pub mod dispatcher;
pub mod format;
pub mod listener;
pub mod template;
