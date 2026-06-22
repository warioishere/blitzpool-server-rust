// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors surfaced by the JDP wrapper.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum JdpError {
    #[error("bitcoin-core IPC socket path does not exist: {0}")]
    SocketPathNotFound(PathBuf),

    #[error("failed to spawn JDP worker thread: {0}")]
    WorkerSpawn(String),

    #[error("JDP worker failed to start: {0}")]
    WorkerStartup(String),

    #[error("JDP worker channel closed before message could be delivered")]
    WorkerChannelClosed,

    #[error("JDP worker dropped DeclareMiningJob response before it could be received")]
    ResponseDropped,

    #[error("JDP worker has already been shut down")]
    AlreadyShutDown,

    #[error("PushSolution extranonce too large for B032 (max 32 bytes, got {0})")]
    ExtranonceTooLarge(usize),
}
