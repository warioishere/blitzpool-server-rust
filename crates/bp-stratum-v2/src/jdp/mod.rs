// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP-server submodule: per-connection state machine, dynamic-coinbase-
//! outputs (ext 0x0003), declared-job storage, transaction validation.

pub mod client;
pub mod custom_job_binding;
pub mod declarations;
pub mod dynamic_outputs;
pub mod payout_distribution;
pub mod tx_validation;
