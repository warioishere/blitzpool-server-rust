// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V1 server: TDP templates become `mining.notify` frames (no
//! `getblocktemplate` polling), with vardiff, share validation and one task
//! per connection. Shares are validated inline because a hash costs microseconds.
//! `mining.notify[5..8]` use the 8-hex-padded ckpool form.

mod client;
mod config;
mod error;
mod frame;
mod hooks;
mod jobs;
mod notify;
mod server;
mod shared_adapter;
mod submit;

pub use config::{PortConfig, ServerConfig, DEFAULT_POOL_IDENTIFIER};
pub use error::StratumV1Error;
pub use frame::parse_request;
pub use hooks::{BlockSubmissionSink, PayoutResolver, ServerHooks};
pub use notify::{build_notify_frame, swap_endian_words, ActiveSV1Template};
pub use server::{SharedExtranonce, StratumV1Server};
pub use submit::ShareAccept;
