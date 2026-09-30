// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V2 — Noise handshake, binary frames, Standard + Extended channels,
//! Job-Declaration server, TDP-translator, group channels.
//!
//! One crate covers both the mining-side server and the miner-facing JDP
//! server, with an internal cross-server bridge that routes JDP-declared
//! jobs to the correct mining channel via `SetCustomMiningJob`.
//!
//! Architecture notes:
//!
//! - **Multi-thread by default.** Per-connection task on the tokio
//!   multi-thread runtime. Per-server (mining + JDP) accept-loops; one
//!   global TDP-translator broadcasts `NewMiningJob`/`NewExtendedMiningJob`
//!   to all subscribed channel-tasks; one global bridge consumes
//!   `DeclaredJobEvent`s from JDP-sessions and dispatches
//!   `SetCustomMiningJob` to the corresponding mining channel.
//! - **Generic SV2 protocol via dependencies.** `stratum_core` (binary,
//!   codec, framing, noise, mining-wire, parsers, JDP/TDP messages) and
//!   `stratum_apps` (Noise-wrapped tokio TcpStream, task manager, key
//!   utils) provide the protocol; this crate holds only the pool-side state
//!   machine and pool behaviour.
//! - **Hooks for I/O.** All side-effects (DB upserts, Redis writes,
//!   notifications, block-submit) flow through `ServerHooks` so that
//!   `bin/blitzpool` can wire production adapters and tests can use
//!   no-op or recording hooks.

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
