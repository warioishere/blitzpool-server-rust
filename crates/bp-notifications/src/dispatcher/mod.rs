// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine-event → adapter fan-out through the [`NotificationDispatcher`].
//! Failures are per-subscriber, so one bad token never breaks the fan-out.
//! Device-status events first pass `device_gate`, which debounces flapping
//! connections and collapses bursts.

mod device_gate;
mod orchestrator;

pub use device_gate::{
    DeviceAggregate, DeviceGateConfig, DeviceKey, DeviceLiveness, DeviceLivenessLookup,
    DeviceNotice, DeviceStatusGate, ReportedStateStore,
};
pub(crate) use orchestrator::{push_fcm, push_web, PUSH_TYPE_FCM, PUSH_TYPE_UNIFIED};
pub use orchestrator::{DeviceStatusEvent, NotificationDispatcher};
