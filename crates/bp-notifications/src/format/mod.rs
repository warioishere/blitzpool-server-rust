// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure de/en formatting helpers shared by the dispatcher and the
//! bot-command surface, kept apart so they can be unit-tested.

mod device_status;
pub mod html;
mod language;
mod number_suffix;
mod sats;

pub use device_status::{
    format_device_time, DeviceAggregateArgs, DeviceAggregateText, DevicePartialArgs,
    DevicePartialText, DeviceStatusArgs, DeviceStatusText,
};
pub use language::Language;
pub use number_suffix::format_number_suffix;
pub use sats::format_sats;
