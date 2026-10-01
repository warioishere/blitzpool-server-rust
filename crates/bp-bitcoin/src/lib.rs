// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auxiliary Bitcoin Core JSON-RPC client for read-only metadata RPCs.
//! Templates, tip tracking and submission of pool-built blocks go through
//! TDP; the one exception is [`BitcoinRpc::submit_block`] for JDP-declared
//! blocks, which have no pool-side `template_id`.

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
