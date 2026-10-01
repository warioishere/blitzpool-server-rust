// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V2 pool side: the mining server and the JDP server in one crate,
//! joined by a bridge that routes JDP-declared jobs to their mining channel.
//! Wire protocol comes from `stratum_core`/`stratum_apps`; this crate holds
//! the pool's state machines, with all side effects behind hooks.

pub mod bridge;
pub mod codec_common;
pub mod extensions;
pub mod extranonce;
pub mod hooks;
pub mod jdp_server;
pub mod jdp_server_codec;
pub mod noise;
pub mod protocol_version;
pub mod server;
pub mod server_codec;
mod shared_adapter;
pub mod tokens;

pub mod jdp;
pub mod mining;
