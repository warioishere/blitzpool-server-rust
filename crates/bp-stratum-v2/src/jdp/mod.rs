// SPDX-License-Identifier: AGPL-3.0-or-later

//! JDP-server submodule: per-connection state machine, dynamic-coinbase-
//! outputs (ext 0x0003), declared-job storage, transaction validation.

pub mod client;
pub mod declarations;
pub mod dynamic_outputs;
pub mod tx_validation;
