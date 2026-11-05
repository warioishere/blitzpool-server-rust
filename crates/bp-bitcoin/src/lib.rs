// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auxiliary Bitcoin Core JSON-RPC client for read-only metadata RPCs.
//! Templates, tip tracking and block submission go through IPC: TDP for
//! pool-built blocks, the JDP validation engine for JDP-declared ones.

mod client;
mod config;
mod error;
mod types;

pub use client::BitcoinRpc;
pub use config::{BitcoinRpcConfig, RpcAuth};
pub use error::{RpcError, RpcErrorDetail};
pub use types::{
    BlockHeaderInfo, BlockTxids, DecodedTransaction, LocalAddress, MiningInfo, NetworkInfo,
    NetworkInfoNetwork, ScriptPubKey, TransactionOutput,
};
