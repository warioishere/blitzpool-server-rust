// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notifications: email templates, outbound transports ([`adapter`]), the
//! engine-event fan-out ([`dispatcher`]), bot commands shared by Telegram and
//! ntfy ([`command`], [`listener`]) and periodic crons ([`cron`]).

pub mod adapter;
pub mod command;
pub mod cron;
pub mod dispatcher;
pub mod format;
pub mod listener;
pub mod template;
