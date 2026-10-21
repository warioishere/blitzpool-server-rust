// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors surfaced by the TDP wrapper.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum TdpError {
    #[error("bitcoin-core IPC socket path does not exist: {0}")]
    SocketPathNotFound(PathBuf),

    /// A found block would be dropped: see `spawn_worker`.
    #[error("cannot create the solutions directory {path} beside the IPC socket: {reason}")]
    SolutionsDir { path: PathBuf, reason: String },

    #[error("failed to spawn TDP worker thread: {0}")]
    WorkerSpawn(String),

    #[error("TDP worker failed to start: {0}")]
    WorkerStartup(String),

    #[error("TDP worker channel closed before message could be delivered")]
    WorkerChannelClosed,

    #[error("TDP worker has already been shut down")]
    AlreadyShutDown,
}
