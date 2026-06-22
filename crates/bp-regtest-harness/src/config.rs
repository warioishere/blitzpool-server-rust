// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default install location of the IPC-enabled `bitcoin-node` binary on the
/// dev machine (see `CHECKLIST.md` for prereqs).
pub const DEFAULT_BITCOIN_NODE_PATH: &str = "/home/warioishere/bitcoin-31.0/libexec/bitcoin-node";

/// Environment variable that, when set, overrides [`DEFAULT_BITCOIN_NODE_PATH`].
pub const BITCOIN_NODE_PATH_ENV: &str = "BITCOIN_NODE_PATH";

/// Maximum wall-time to wait for bitcoin-node to come up (cookie file +
/// IPC socket + first RPC response). bitcoin-core normally needs 1-2s on a
/// warm tmpfs; 30s is a generous ceiling that still bounds hung-test damage.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct RegtestConfig {
    pub bitcoin_node_path: PathBuf,
    pub startup_timeout: Duration,
    /// Extra args appended verbatim to the bitcoin-node invocation.
    /// Useful for `-debug=net`, `-printtoconsole`, etc.
    pub extra_args: Vec<String>,
    /// When `Some`, the node uses this datadir instead of an internally
    /// owned tempdir, and does NOT delete it on shutdown/drop. The caller
    /// owns the directory's lifecycle. Lets a test restart bitcoin-node
    /// at the same datadir (= same IPC socket path) to exercise
    /// reconnect/resume paths across a `bitcoind` restart.
    pub external_datadir: Option<PathBuf>,
}

impl Default for RegtestConfig {
    fn default() -> Self {
        let bitcoin_node_path = std::env::var(BITCOIN_NODE_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_BITCOIN_NODE_PATH));
        Self {
            bitcoin_node_path,
            startup_timeout: Duration::from_secs(DEFAULT_STARTUP_TIMEOUT_SECS),
            extra_args: Vec::new(),
            external_datadir: None,
        }
    }
}

impl RegtestConfig {
    pub fn with_bitcoin_node_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.bitcoin_node_path = path.into();
        self
    }

    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }

    pub fn with_extra_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.extra_args = args.into_iter().collect();
        self
    }

    /// Use a caller-owned datadir instead of an internal tempdir. The
    /// node will NOT delete it on shutdown — the caller is responsible
    /// for cleanup. See [`RegtestConfig::external_datadir`].
    pub fn with_external_datadir(mut self, datadir: impl Into<PathBuf>) -> Self {
        self.external_datadir = Some(datadir.into());
        self
    }

    /// Return `Ok(())` if the configured binary path exists and is
    /// executable. Lets callers fast-skip integration tests on machines
    /// without bitcoin-core installed.
    pub fn is_available(&self) -> bool {
        self.bitcoin_node_path.exists() && is_executable(&self.bitcoin_node_path)
    }
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    // No env-var mutation test — Rust 1.85 marks `set_var`/`remove_var` as
    // unsafe and `unsafe_code = "deny"` is on for the workspace. The env
    // var is read once at `RegtestConfig::default()` call time; a fresh
    // process with `BITCOIN_NODE_PATH=...` set would observe it.

    #[test]
    fn builder_overrides_path_and_timeout() {
        let cfg = RegtestConfig::default()
            .with_bitcoin_node_path("/x/bitcoin-node")
            .with_startup_timeout(Duration::from_secs(5));
        assert_eq!(cfg.bitcoin_node_path, PathBuf::from("/x/bitcoin-node"));
        assert_eq!(cfg.startup_timeout, Duration::from_secs(5));
    }

    #[test]
    fn missing_binary_is_unavailable() {
        let cfg = RegtestConfig::default().with_bitcoin_node_path("/definitely/not/here");
        assert!(!cfg.is_available());
    }
}
