// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stratum V2 — Noise handshake, binary frames, Standard + Extended channels,
//! Job-Declaration server, TDP-translator, group channels.
//!
//! Module-by-module per `MIGRATION_PLAN.md`. See
//! `CHECKLIST.md` for the live status. Architecture sketch agreed
//! 2026-05-16: single crate covers both the mining-side server and the
//! miner-facing JDP server, with an internal cross-server bridge for
//! routing JDP-declared jobs to the correct mining channel via
//! `SetCustomMiningJob`.
//!
//! Architecture notes:
//!
//! - **Multi-thread by default.** Per-connection task on the tokio
//!   multi-thread runtime. Per-server (mining + JDP) accept-loops; one
//!   global TDP-translator broadcasts `NewMiningJob`/`NewExtendedMiningJob`
//!   to all subscribed channel-tasks; one global bridge consumes
//!   `DeclaredJobEvent`s from JDP-sessions and dispatches
//!   `SetCustomMiningJob` to the corresponding mining channel.
//! - **Generic SV2 protocol via runtime-deps.** `stratum_core` (binary,
//!   codec, framing, noise, mining-wire, parsers, JDP/TDP messages) and
//!   `stratum_apps` (Noise-wrapped tokio TcpStream, task manager, key
//!   utils) are git+rev-pinned runtime-deps per the 2026-05-16 strategy
//!   decision. Eigen-Code only for pool-side state machine + Blitzpool
//!   behaviour.
//! - **Functional reactions** (frame shape, vendor quirks,
//!   retire-not-clear job lifecycle from sv2-ui#143, jobIdToDifficulty
//!   for SV2 §5.3.14, stored-merkle-root to avoid mutation bugs,
//!   dust-suppression in JDP ext 0x0003) are implemented as specified.
//!   Internal performance improvements are allowed where they don't
//!   change observable behaviour.
//! - **Hooks for I/O.** All side-effects (DB upserts, Redis writes,
//!   notifications, block-submit) flow through `ServerHooks` so that
//!   `bin/blitzpool` can wire production adapters and tests can use
//!   no-op or recording hooks.

pub mod bridge;
pub mod config;
pub mod error;
pub mod extensions;
pub mod extranonce;
pub mod hooks;
pub mod jdp_server;
pub mod jdp_server_codec;
pub mod noise;
pub mod server;
pub mod server_codec;
pub mod shared_adapter;
pub mod tokens;

pub mod jdp;
pub mod mining;
