// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound notification transports. Hard failures return [`AdapterError`];
//! the caller logs and moves on to the next subscriber, so one bad token
//! never breaks the fan-out.

mod error;
mod fcm;
mod ntfy;
mod payload;
mod smtp;
mod telegram;
mod web_push;

pub use error::{AdapterError, AdapterResult};
pub use fcm::{FcmAdapter, FcmConfig, FcmOutcome, FcmServiceAccount};
pub use ntfy::{NtfyAdapter, NtfyConfig};
pub use payload::{PushKind, PushPayload};
pub use smtp::{SmtpAdapter, SmtpConfig};
pub use telegram::{InlineButton, InlineKeyboard, TelegramAdapter, TelegramConfig};
pub use web_push::{VapidConfig, WebPushAdapter, WebPushOutcome};
