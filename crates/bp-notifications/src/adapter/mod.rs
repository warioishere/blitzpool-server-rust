// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound notification transports.
//!
//! Each adapter owns its own configuration + client (HTTP / SMTP) and
//! exposes a small send-API tailored to the transport. They are
//! constructed once at startup and shared across the dispatcher via `Arc`.
//!
//! Failure semantics: adapters return [`AdapterError`] on hard failures
//! (config invalid, network down, auth rejected). Caller logs and
//! continues to the next subscriber — a single bad token never breaks
//! the fan-out. FCM/Web-Push expose an extra `InvalidRecipient` variant
//! so the dispatcher can soft-delete the dead subscription row.

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
