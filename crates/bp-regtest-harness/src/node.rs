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
    /// `Option` so [`RegtestNode::shutdown`] can take it out before `Drop`.
    child: Option<Child>,
    /// `Some` only for an owned tempdir; `None` with
    /// [`RegtestConfig::external_datadir`], which survives a node restart.
    datadir_guard: Option<TempDir>,
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
                // Kill before surfacing the error so the process doesn't leak.
                node.kill_quietly();
                Err(e)
            }
        }
    }

    async fn wait_for_ready(&mut self, timeout: Duration) -> Result<(), RegtestError> {
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

    /// Peek for process death without blocking. `try_wait` rather than
    /// `/proc`, which macOS lacks, and it yields the real exit status.
    fn check_alive(&mut self) -> Result<(), RegtestError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        let pid = child.id();
        match child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(RegtestError::ExitedDuringStartup(format!(
                "bitcoin-node pid {pid} exited with {status}"
            ))),
            // Only reachable if the child was already reaped elsewhere; not
            // evidence of a startup failure, so don't report one.
            Err(e) => {
                debug!(error = %e, pid, "regtest: try_wait failed, assuming alive");
                Ok(())
            }
        }
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
    /// by [`RegtestNode::generate_to_self`]; exposed publicly for tests
    /// that drive the wallet directly.
    pub async fn ensure_wallet(&self) -> Result<(), RegtestError> {
        match self
            .rpc
            .call("createwallet", json!([DEFAULT_WALLET_NAME]))
            .await
        {
            Ok(_) => Ok(()),
            Err(RegtestError::Rpc { detail, .. }) if detail.contains("already loaded") => Ok(()),
            // On disk but not loaded, e.g. after a restart at the same
            // datadir; `createwallet` does not load it, so `loadwallet` must.
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
                // The wallet may be pre-loaded or present but not auto-loaded.
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

    /// Generic wallet RPC passthrough (URL carries the wallet path).
    pub async fn wallet_call(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, RegtestError> {
        self.ensure_wallet().await?;
        self.wallet_rpc(method, params).await
    }

    /// Generic node (non-wallet) RPC passthrough.
    pub async fn rpc_call(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, RegtestError> {
        self.rpc.call(method, params).await
    }

    async fn wallet_rpc(&self, method: &'static str, params: Value) -> Result<Value, RegtestError> {
        // Wallet RPCs need the wallet name in the URL path.
        let wallet_url = format!(
            "http://127.0.0.1:{}/wallet/{}",
            self.rpc_port, DEFAULT_WALLET_NAME
        );
        let wallet_caller = RpcCaller::new(wallet_url, self.cookie_path());
        wallet_caller.call(method, params).await
    }

    /// Fresh wallet address; `address_type` is `getnewaddress`'s second
    /// argument (`"legacy"`, `"p2sh-segwit"`, `"bech32"`, `"bech32m"`).
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

    /// Hex compressed pubkey of a wallet address, via `getaddressinfo`.
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

    /// Submit a raw block (hex): `None` if accepted, `Some(reason)` if rejected.
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

    /// Mine `n` blocks whose coinbase pays `address`. Returns the tip height.
    pub async fn generate_to_address(&self, n: u32, address: &str) -> Result<u32, RegtestError> {
        self.ensure_wallet().await?;
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
            // `stop` flushes chainstate so the process exits cleanly.
            let _ = self.rpc.call("stop", json!([])).await;
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
        // Close explicitly so cleanup errors are logged, not swallowed by `Drop`.
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
            // No async context here for a graceful `stop`, so SIGKILL.
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
