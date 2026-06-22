// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mining-protocol roof: per-connection state machine, channel state,
//! job lifecycle, vardiff, share-validation pipeline, TDP-translator,
//! group-channels.

pub mod channel;
pub mod client;
pub mod groups;
pub mod jobs;
pub mod submit;
pub mod translator;
pub mod vardiff;
