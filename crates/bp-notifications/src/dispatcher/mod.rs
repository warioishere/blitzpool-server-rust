// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine-event → adapter fan-out.
//!
//! The [`NotificationDispatcher`] is built once at startup with whichever
//! adapters are configured (any can be `None` to disable that transport),
//! then engines call its `notify_*` methods on every relevant share /
//! block / device event. Internally it looks up subscriptions in
//! `bp-db`, formats the message per language, and parallel-fan-outs to
//! every adapter that the address has subscribed for. Failures are
//! per-subscriber: a single bad token doesn't break the fan-out.

mod config;
mod orchestrator;

pub use config::DispatcherConfig;
pub use orchestrator::{DeviceStatusEvent, NotificationDispatcher};
