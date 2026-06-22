// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared formatting helpers used by the dispatcher when turning
//! engine events into per-language adapter messages.
//!
//! Lives in its own module so the helpers can be unit-tested (pure
//! functions) and reused later by the bot-command surface (which
//! produces the same de/en messages on demand).

mod device_status;
mod language;
mod number_suffix;

pub use device_status::{format_device_time, DeviceStatusArgs, DeviceStatusText};
pub use language::Language;
pub use number_suffix::format_number_suffix;
