// SPDX-License-Identifier: AGPL-3.0-or-later

//! `RegtestNode` — owns the lifecycle of a single `bitcoin-node -regtest`
//! process with SV2 IPC enabled.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::TempDir;
use tracing::{debug, info, warn};

use bp_bitcoin::{BitcoinRpc, BitcoinRpcConfig, RpcAuth};

use crate::config::RegtestConfig;
use crate::error::RegtestError;
use crate::rpc::RpcCaller;

const DEFAULT_WALLET_NAME: &str = "bp_regtest";

/// A running bitcoin-node in regtest mode, ready for SV2 IPC + JSON-RPC.
///
/// Not `Clone` — there is exactly one underlying process per instance. Pass
/// `&RegtestNode` around if multiple tasks need access.
pub struct RegtestNode {
    /// The bitcoin-node child. Wrapped in `Option` so we can take it out in
    /// [`shutdown`] without leaving an invalid `Child` behind for `Drop`.
    child: Option<Child>,
    /// Owned tempdir backing `<datadir>` — `Some` only when the node
    /// created its own datadir (deleted on shutdown/drop). `None` when an
    /// external datadir was supplied via
    /// [`RegtestConfig::external_datadir`] (caller owns cleanup, so the
    /// directory survives a node restart).
    datadir_guard: Option<TempDir>,
    /// Resolved datadir path — valid regardless of whether the directory
    /// is internally owned or external.
    datadir_path: PathBuf,
    rpc_port: u16,
    p2p_port: u16,
    rpc: RpcCaller,
}

impl RegtestNode {
    /// Convenience: spawn with [`RegtestConfig::default`]. Most tests want
    /// this.
    pub async fn start() -> Result<Self, RegtestError> {
        Self::start_with(RegtestConfig::default()).await
    }

    /// Spawn a fresh bitcoin-node with the given config and block until it
    /// is ready to accept RPC and SV2 IPC connections.
    pub async fn start_with(config: RegtestConfig) -> Result<Self, RegtestError> {
        if !config.bitcoin_node_path.exists() {
            return Err(RegtestError::BinaryNotFound(
                config.bitcoin_node_path.clone(),
            ));
        }

        // Either use the caller-supplied external datadir (survives node
        // restarts) or create an owned tempdir (auto-cleaned on drop).
        let (datadir_guard, datadir_path) = match &config.external_datadir {
            Some(path) => {
                std::fs::create_dir_all(path).map_err(RegtestError::Io)?;
                (None, path.clone())
            }
            None => {
                let dir = tempfile::Builder::new()
                    .prefix("bp-rt-")
                    .tempdir()
                    .map_err(RegtestError::Io)?;
                let path = dir.path().to_path_buf();
                (Some(dir), path)
            }
        };

        let rpc_port = allocate_free_port()?;
        let p2p_port = allocate_free_port()?;

        info!(
            datadir = %datadir_path.display(),
            rpc_port,
            p2p_port,
            "spawning bitcoin-node regtest"
        );

        let mut cmd = Command::new(&config.bitcoin_node_path);
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", datadir_path.display()))
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .arg("-rpcallowip=127.0.0.1")
            .arg("-rpcbind=127.0.0.1")
            .arg("-ipcbind=unix")
            .arg("-fallbackfee=0.0001")
            .arg("-listen=0")
            .arg("-discover=0")
            .arg("-dnsseed=0")
            .arg("-server=1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for extra in &config.extra_args {
            cmd.arg(extra);
        }

        let child = cmd
            .spawn()
            .map_err(|e| RegtestError::Spawn(e.to_string()))?;

        let cookie_path = datadir_path.join("regtest").join(".cookie");
        let rpc_url = format!("http://127.0.0.1:{rpc_port}");
        let rpc = RpcCaller::new(rpc_url, cookie_path.clone());

        let mut node = Self {
            child: Some(child),
            datadir_guard,
            datadir_path,
            rpc_port,
            p2p_port,
            rpc,
        };

        match node.wait_for_ready(config.startup_timeout).await {
            Ok(()) => Ok(node),
            Err(e) => {
                // best-effort kill before surfacing the error so the
                // bitcoin-node process doesn't leak.
                node.kill_quietly();
                Err(e)
            }
        }
    }

    async fn wait_for_ready(&self, timeout: Duration) -> Result<(), RegtestError> {
        let deadline = Instant::now() + timeout;
        let cookie_path = self.cookie_path();

        // 1) cookie file appears.
        while !cookie_path.exists() {
            self.check_alive()?;
            if Instant::now() >= deadline {
                return Err(RegtestError::Timeout {
                    what: "cookie file",
                    seconds: timeout.as_secs(),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        debug!("regtest: cookie file present");

        // 2) RPC responds to getblockchaininfo.
        loop {
            self.check_alive()?;
            match self.rpc.call("getblockchaininfo", json!([])).await {
                Ok(_) => break,
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(e) => return Err(e),
            }
        }
        debug!("regtest: RPC alive");

        // 3) IPC socket appears.
        let ipc_path = self.ipc_socket_path();
        while !ipc_path.exists() {
            self.check_alive()?;
            if Instant::now() >= deadline {
                return Err(RegtestError::Timeout {
                    what: "IPC socket",
                    seconds: timeout.as_secs(),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        info!(
            ipc_socket = %ipc_path.display(),
            "regtest: ready (cookie + RPC + IPC socket all up)"
        );
        Ok(())
    }

    fn check_alive(&self) -> Result<(), RegtestError> {
        // SAFETY-NOTE: `try_wait` does not block; we only need to peek for
        // process death. `child` is always `Some` between construction and
        // shutdown.
        if let Some(child) = self.child.as_ref() {
            // try_wait requires &mut, but we only have &self here. We use a
            // workaround: send SIGCHLD is not available without raw libc, so
            // we accept that this check is best-effort by checking the pid
            // through /proc.
            let pid = child.id();
            let alive = std::fs::metadata(format!("/proc/{pid}")).is_ok();
            if !alive {
                return Err(RegtestError::ExitedDuringStartup(format!(
                    "bitcoin-node pid {pid} no longer running"
                )));
            }
        }
        Ok(())
    }

    /// IPC socket path that bitcoin-node creates when `-ipcbind=unix` is
    /// passed. The fixed name `node.sock` is bitcoin-core's convention.
    pub fn ipc_socket_path(&self) -> PathBuf {
        self.datadir_path().join("regtest").join("node.sock")
    }

    /// RPC cookie file written by bitcoin-node on startup.
    pub fn cookie_path(&self) -> PathBuf {
        self.datadir_path().join("regtest").join(".cookie")
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    pub fn p2p_port(&self) -> u16 {
        self.p2p_port
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    /// Path to the `<datadir>` (without the network subdir).
    pub fn datadir_path(&self) -> &Path {
        &self.datadir_path
    }

    /// Build a production-shape [`BitcoinRpc`] handle pointed at this node,
    /// so test code can exercise the same client surface that pool code uses.
    pub fn bitcoin_rpc(&self) -> Result<BitcoinRpc, bp_bitcoin::RpcError> {
        let cfg = BitcoinRpcConfig {
            url: self.rpc_url(),
            auth: RpcAuth::Cookie(self.cookie_path()),
            timeout: Some(Duration::from_secs(30)),
        };
        BitcoinRpc::new(cfg)
    }

    /// Make sure a default wallet exists and is loaded. Called automatically
    /// by [`generate_to_self`]; exposed publicly for tests that drive the
    /// wallet directly.
    pub async fn ensure_wallet(&self) -> Result<(), RegtestError> {
        match self
            .rpc
            .call("createwallet", json!([DEFAULT_WALLET_NAME]))
            .await
        {
            // Freshly created (and therefore loaded).
            Ok(_) => Ok(()),
            // Already loaded in this process → nothing to do.
            Err(RegtestError::Rpc { detail, .. }) if detail.contains("already loaded") => Ok(()),
            // Wallet exists on disk but is NOT loaded — the common case
            // after a node restart at the same datadir (createwallet
            // reports "Database already exists"). createwallet does NOT
            // load it, so we must `loadwallet` explicitly; otherwise the
            // first wallet RPC fails with -18 "wallet not loaded".
            Err(RegtestError::Rpc { detail, .. }) if detail.contains("already exists") => {
                match self
                    .rpc
                    .call("loadwallet", json!([DEFAULT_WALLET_NAME]))
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(RegtestError::Rpc { detail, .. }) if detail.contains("already loaded") => {
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => {
                // Some bitcoin-core configurations may pre-load the default
                // wallet; loadwallet may also be necessary if the wallet was
                // present from a previous run but not auto-loaded.
                if let Err(load_err) = self
                    .rpc
                    .call("loadwallet", json!([DEFAULT_WALLET_NAME]))
                    .await
                {
                    if !format!("{load_err}").contains("already loaded") {
                        return Err(e);
                    }
                }
                Ok(())
            }
        }
    }

    /// Generic **wallet** RPC passthrough (URL carries the wallet path).
    /// For tests that need to fund a wallet + fill the mempool —
    /// `sendmany`, `createrawtransaction`, `fundrawtransaction`, etc.
    pub async fn wallet_call(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, RegtestError> {
        self.ensure_wallet().await?;
        self.wallet_rpc(method, params).await
    }

    /// Generic **node** (non-wallet) RPC passthrough — `getmempoolinfo`,
    /// `getblocktemplate`, `getrawmempool`, etc.
    pub async fn rpc_call(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, RegtestError> {
        self.rpc.call(method, params).await
    }

    async fn wallet_rpc(&self, method: &'static str, params: Value) -> Result<Value, RegtestError> {
        // Bitcoin-core wallet RPCs require the URL to include the wallet
        // name as a path component. We construct a per-wallet RpcCaller on
        // the fly rather than maintain a separate field — call rate is low.
        let wallet_url = format!(
            "http://127.0.0.1:{}/wallet/{}",
            self.rpc_port, DEFAULT_WALLET_NAME
        );
        let wallet_caller = RpcCaller::new(wallet_url, self.cookie_path());
        wallet_caller.call(method, params).await
    }

    /// Fresh wallet-derived address of the given type. `address_type` is
    /// passed directly to bitcoin-core's `getnewaddress` second argument
    /// (`"legacy"` → P2PKH, `"p2sh-segwit"` → P2SH-P2WPKH, `"bech32"` →
    /// P2WPKH, `"bech32m"` → P2TR). Used by the address-type-coverage
    /// regtest to source one address of each type the pool supports.
    pub async fn new_address(&self, address_type: &str) -> Result<String, RegtestError> {
        self.ensure_wallet().await?;
        let value = self
            .wallet_rpc("getnewaddress", json!(["", address_type]))
            .await?;
        serde_json::from_value(value).map_err(|e| RegtestError::Rpc {
            method: "getnewaddress",
            detail: format!("expected string address, got: {e}"),
        })
    }

    /// Hex-encoded compressed pubkey for a wallet-derived bech32 address.
    /// Wraps `getaddressinfo` and pulls the `pubkey` field. Used by the
    /// 5-address-type regtest to derive a P2WSH (wrap an inner P2WPKH
    /// script around a real on-chain pubkey via P2WSH).
    pub async fn address_pubkey_hex(&self, address: &str) -> Result<String, RegtestError> {
        self.ensure_wallet().await?;
        let value = self.wallet_rpc("getaddressinfo", json!([address])).await?;
        value
            .get("pubkey")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| RegtestError::Rpc {
                method: "getaddressinfo",
                detail: format!("no `pubkey` field for address {address}"),
            })
    }

    /// Submit a fully-assembled raw block (hex). Returns `None` on
    /// accepted; `Some(reason)` on rejected. Used by regtests that
    /// build blocks via the SV1 `MiningJob` path (no TDP
    /// `SubmitSolution` round-trip).
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>, RegtestError> {
        let value = self.rpc.call("submitblock", json!([block_hex])).await?;
        match value {
            Value::Null => Ok(None),
            Value::String(reason) => Ok(Some(reason)),
            other => Err(RegtestError::Rpc {
                method: "submitblock",
                detail: format!("unexpected submitblock result: {other}"),
            }),
        }
    }

    /// Mine `n` blocks to a fresh address from the harness's default wallet.
    /// Returns the resulting tip height.
    pub async fn generate_to_self(&self, n: u32) -> Result<u32, RegtestError> {
        self.ensure_wallet().await?;
        let address: String = serde_json::from_value(
            self.wallet_rpc("getnewaddress", json!([])).await?,
        )
        .map_err(|e| RegtestError::Rpc {
            method: "getnewaddress",
            detail: format!("expected string address, got: {e}"),
        })?;
        let _hashes = self
            .wallet_rpc("generatetoaddress", json!([n, address]))
            .await?;
        self.current_height().await
    }

    /// Current tip height via `getblockchaininfo`.
    pub async fn current_height(&self) -> Result<u32, RegtestError> {
        let info = self.rpc.call("getblockchaininfo", json!([])).await?;
        info.get("blocks")
            .and_then(Value::as_u64)
            .map(|h| h as u32)
            .ok_or_else(|| RegtestError::Rpc {
                method: "getblockchaininfo",
                detail: "missing or non-numeric `blocks` field".into(),
            })
    }

    /// Block until tip reaches `target` height. Polls every 50 ms.
    pub async fn wait_for_height(
        &self,
        target: u32,
        timeout: Duration,
    ) -> Result<(), RegtestError> {
        let deadline = Instant::now() + timeout;
        loop {
            let h = self.current_height().await?;
            if h >= target {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(RegtestError::Timeout {
                    what: "tip height",
                    seconds: timeout.as_secs(),
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Stop the node cleanly. Idempotent.
    pub async fn shutdown(mut self) -> Result<(), RegtestError> {
        if let Some(mut child) = self.child.take() {
            // bitcoin-core flushes chainstate on the `stop` RPC; do that
            // first so the process exits cleanly.
            let _ = self.rpc.call("stop", json!([])).await;
            // Give it up to 5 seconds to exit gracefully.
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_status)) => break,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            warn!("regtest: bitcoin-node did not exit on `stop` RPC, killing");
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "regtest: try_wait failed, killing");
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
        // Drop the owned tempdir explicitly so cleanup errors are surfaced
        // via the tracing log rather than swallowed by `Drop`. An external
        // datadir (`datadir_guard == None`) is left intact for the caller.
        if let Some(dir) = self.datadir_guard.take() {
            if let Err(e) = dir.close() {
                warn!(error = %e, "regtest: failed to remove datadir");
            }
        }
        Ok(())
    }

    fn kill_quietly(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Fast path on Drop: SIGKILL the process. We don't have an async
            // context here, so a graceful `stop` RPC isn't viable. Tempdir
            // cleanup happens automatically when `self.datadir_guard` drops
            // (owned tempdir only; external datadirs are left for the caller).
            if let Err(e) = child.kill() {
                debug!(error = %e, "regtest: kill on Drop failed (process may already be gone)");
            }
            let _ = child.wait();
        }
    }
}

fn allocate_free_port() -> Result<u16, RegtestError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| RegtestError::PortAlloc(format!("bind failed: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| RegtestError::PortAlloc(format!("local_addr failed: {e}")))?
        .port();
    drop(listener);
    Ok(port)
}
