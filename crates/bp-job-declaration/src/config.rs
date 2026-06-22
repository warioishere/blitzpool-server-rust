// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime configuration for the JDP wrapper.

use std::path::PathBuf;

/// Default capacity of the inbound mpsc that carries
/// `declare_mining_job` / `push_solution` requests to the worker.
/// 32 is enough to absorb a small burst without bloating memory; back-
/// pressure kicks in beyond that.
pub const DEFAULT_REQUEST_CAPACITY: usize = 32;

#[derive(Debug, Clone)]
pub struct JdpConfig {
    pub socket_path: PathBuf,
    pub request_capacity: usize,
}

impl JdpConfig {
    /// Build a config with all defaults except the bitcoin-core IPC socket
    /// path, which is mandatory. By convention, JDP shares the same socket
    /// as TDP — bitcoin-core multiplexes both protocols over the single
    /// `-ipcbind` UNIX domain socket.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            request_capacity: DEFAULT_REQUEST_CAPACITY,
        }
    }

    pub fn with_request_capacity(mut self, capacity: usize) -> Self {
        self.request_capacity = capacity;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let cfg = JdpConfig::new("/tmp/anything.sock");
        assert_eq!(cfg.request_capacity, 32);
    }

    #[test]
    fn builder_overrides_chain() {
        let cfg = JdpConfig::new("/x.sock").with_request_capacity(8);
        assert_eq!(cfg.request_capacity, 8);
    }
}
