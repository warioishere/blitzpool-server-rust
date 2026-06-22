// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public messages exchanged with the JDP wrapper.
//!
//! Unlike TDP, JDP is purely request/response — there is no outbound stream
//! of events from bitcoin-core. So the public types here describe what the
//! pool sends in:
//!
//! - [`PushSolutionRequest`] is an owned, `Send` wrap around
//!   `job_declaration_sv2::PushSolution<'static>`, mirroring the pattern in
//!   [`crate::TemplateUpdate`](../../../bp-template-distribution/src/message.rs)
//!   used by `bp-template-distribution`.
//! - [`DeclareMiningJobResult`] is what `declare_mining_job` resolves to.
//!   It re-exposes the upstream `JdResponse` variants without any wrapping
//!   because their fields are rust-bitcoin types (`BlockHash`, `Txid`,
//!   `Wtxid`, `CompactTarget`) that we already publicly depend on via
//!   `bitcoin = "0.32"`.

use bitcoin::{BlockHash, CompactTarget, Txid, Wtxid};
use bitcoin_core_sv2::job_declaration_protocol::io::{
    JdResponse as UpstreamJdResponse, ValidationContext as UpstreamValidationContext,
};

use crate::error::JdpError;

/// Owned, `Send` wrap around the SV2 `PushSolution` payload. The pool
/// constructs one of these from miner shares and hands it to
/// [`crate::JdpHandle::push_solution`].
#[derive(Debug, Clone)]
pub struct PushSolutionRequest {
    /// Full extranonce that forms a valid submission. Up to 32 bytes.
    pub extranonce: Vec<u8>,
    /// Previous block hash, exactly as it must appear in the header (LE).
    pub prev_hash: [u8; 32],
    /// `nTime` field of the solved header.
    pub ntime: u32,
    /// Header nonce.
    pub nonce: u32,
    /// Compact-target `nBits` field of the solved header.
    pub nbits: u32,
    /// Header version field.
    pub version: u32,
}

impl PushSolutionRequest {
    /// Convert into the wire-level `PushSolution<'static>` payload. Returns
    /// [`JdpError::ExtranonceTooLarge`] if the extranonce exceeds 32 bytes
    /// (the SV2 `B032` upper bound).
    pub(crate) fn into_upstream(
        self,
    ) -> Result<stratum_core::job_declaration_sv2::PushSolution<'static>, JdpError> {
        let extranonce_len = self.extranonce.len();
        let extranonce = stratum_core::binary_sv2::B032::try_from(self.extranonce)
            .map_err(|_| JdpError::ExtranonceTooLarge(extranonce_len))?;
        let prev_hash = stratum_core::binary_sv2::U256::from(self.prev_hash);
        Ok(stratum_core::job_declaration_sv2::PushSolution {
            extranonce,
            prev_hash,
            ntime: self.ntime,
            nonce: self.nonce,
            nbits: self.nbits,
            version: self.version,
        })
    }
}

/// Validation context snapshot returned together with errors so callers can
/// distinguish stale-tip races from other failures.
#[derive(Debug, Clone, Copy)]
pub struct ValidationContext {
    pub prev_hash: BlockHash,
    pub nbits: CompactTarget,
    pub min_ntime: u32,
}

impl From<UpstreamValidationContext> for ValidationContext {
    fn from(value: UpstreamValidationContext) -> Self {
        Self {
            prev_hash: value.prev_hash,
            nbits: value.nbits,
            min_ntime: value.min_ntime,
        }
    }
}

/// Result of a `declare_mining_job` call.
#[derive(Debug, Clone)]
pub enum DeclareMiningJobResult {
    /// bitcoin-core accepted the declared job. The pool may now build the
    /// `SetCustomMiningJob` and dispatch it on extended SV2 channels.
    Success {
        prev_hash: BlockHash,
        nbits: CompactTarget,
        min_ntime: u32,
        /// Txids (excluding coinbase), in declaration order. Lets the caller
        /// rebuild the txid merkle tree for validating
        /// `SetCustomMiningJob.merkle_path`.
        txid_list: Vec<Txid>,
    },
    /// bitcoin-core rejected the declared job.
    Error {
        error_code: String,
        validation_context: ValidationContext,
    },
    /// bitcoin-core's mempool is missing some of the declared transactions.
    /// The caller should fetch them and retry `declare_mining_job` with
    /// `missing_txs` populated.
    MissingTransactions {
        missing_wtxids: Vec<Wtxid>,
        validation_context: ValidationContext,
    },
}

impl From<UpstreamJdResponse> for DeclareMiningJobResult {
    fn from(value: UpstreamJdResponse) -> Self {
        match value {
            UpstreamJdResponse::Success {
                prev_hash,
                nbits,
                min_ntime,
                txid_list,
            } => Self::Success {
                prev_hash,
                nbits,
                min_ntime,
                txid_list,
            },
            UpstreamJdResponse::Error {
                error_code,
                validation_context,
            } => Self::Error {
                error_code,
                validation_context: validation_context.into(),
            },
            UpstreamJdResponse::MissingTransactions {
                missing_wtxids,
                validation_context,
            } => Self::MissingTransactions {
                missing_wtxids,
                validation_context: validation_context.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_solution_request_into_upstream_roundtrip() {
        let req = PushSolutionRequest {
            extranonce: vec![0xaa, 0xbb, 0xcc],
            prev_hash: [0x42; 32],
            ntime: 1_700_000_000,
            nonce: 0xdead_beef,
            nbits: 0x1d00_ffff,
            version: 0x2000_0000,
        };
        let upstream = req.into_upstream().expect("valid extranonce length");
        assert_eq!(upstream.extranonce.inner_as_ref(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(upstream.prev_hash.inner_as_ref(), &[0x42; 32]);
        assert_eq!(upstream.ntime, 1_700_000_000);
        assert_eq!(upstream.nonce, 0xdead_beef);
        assert_eq!(upstream.nbits, 0x1d00_ffff);
        assert_eq!(upstream.version, 0x2000_0000);
    }

    #[test]
    fn push_solution_request_rejects_oversized_extranonce() {
        let req = PushSolutionRequest {
            extranonce: vec![0u8; 33],
            prev_hash: [0u8; 32],
            ntime: 0,
            nonce: 0,
            nbits: 0,
            version: 0,
        };
        let err = req.into_upstream().expect_err("33 bytes > B032 cap");
        assert!(matches!(err, JdpError::ExtranonceTooLarge(33)));
    }

    #[test]
    fn validation_context_passthrough() {
        use bitcoin::hashes::Hash;
        let upstream = UpstreamValidationContext {
            prev_hash: BlockHash::from_byte_array([0xa1; 32]),
            nbits: CompactTarget::from_consensus(0x1d00_ffff),
            min_ntime: 1_700_000_001,
        };
        let local: ValidationContext = upstream.into();
        assert_eq!(local.prev_hash, upstream.prev_hash);
        assert_eq!(local.nbits, upstream.nbits);
        assert_eq!(local.min_ntime, 1_700_000_001);
    }
}
