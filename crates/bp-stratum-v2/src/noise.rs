// SPDX-License-Identifier: AGPL-3.0-or-later

//! Noise-XK wiring over [`stratum_apps::network_helpers::accept_noise_connection`],
//! which owns the handshake and framing. This module holds the pool's authority
//! keys and issues each connection a fresh cert valid for [`DEFAULT_CERT_VALIDITY`],
//! so only the cert rotates and that needs no shared state.

use std::time::Duration;

use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::{accept_noise_connection, Error as NoiseHelpersError};
use tokio::net::TcpStream;

// ── Re-exports — let consumers import via `crate::noise::*` ─────────

pub use stratum_apps::network_helpers::noise_stream::{
    NoiseTcpReadHalf, NoiseTcpStream, NoiseTcpWriteHalf,
};

/// Errors from [`accept_pool_noise`]: the upstream
/// [`stratum_apps::network_helpers::Error`] under a short pool-side alias.
pub type NoiseError = NoiseHelpersError;

// ── Constants ───────────────────────────────────────────────────────

/// Per-connection Noise cert validity: 12 hours. Short enough that a leaked
/// cert expires on its own, without revocation tooling; a reconnect gets a
/// fresh one.
pub const DEFAULT_CERT_VALIDITY: Duration = Duration::from_secs(12 * 3600);

// ── NoiseConfig ─────────────────────────────────────────────────────

/// Pool-side Noise-handshake configuration: the parsed authority key-pair.
/// Every connection's cert is issued for [`DEFAULT_CERT_VALIDITY`]. Cloned
/// into both the mining-server and JDP-server accept loops.
#[derive(Clone, Debug)]
pub struct NoiseConfig {
    authority_pub: Secp256k1PublicKey,
    authority_prv: Secp256k1SecretKey,
}

impl NoiseConfig {
    pub fn new(authority_pub: Secp256k1PublicKey, authority_prv: Secp256k1SecretKey) -> Self {
        Self {
            authority_pub,
            authority_prv,
        }
    }

    pub fn authority_pub(&self) -> &Secp256k1PublicKey {
        &self.authority_pub
    }

    pub fn authority_prv(&self) -> &Secp256k1SecretKey {
        &self.authority_prv
    }
}

// ── accept_pool_noise ───────────────────────────────────────────────

/// Accept a freshly-connected `TcpStream` as a Noise responder with the
/// [`NoiseConfig`] keys. The handshake timeout is internal to `stratum_apps`;
/// a failed handshake only ends the connection.
pub async fn accept_pool_noise(
    stream: TcpStream,
    config: &NoiseConfig,
) -> Result<NoiseTcpStream, NoiseError> {
    accept_noise_connection(
        stream,
        config.authority_pub,
        config.authority_prv,
        DEFAULT_CERT_VALIDITY.as_secs(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public test key-pair from the standard SV2 example pool config.
    const TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    #[test]
    fn default_cert_validity_is_12_hours() {
        assert_eq!(DEFAULT_CERT_VALIDITY, Duration::from_secs(12 * 3600));
    }

    #[test]
    fn new_holds_the_sri_test_keys() {
        let pub_k: Secp256k1PublicKey = TEST_PUB.parse().unwrap();
        let prv_k: Secp256k1SecretKey = TEST_PRV.parse().unwrap();
        let cfg = NoiseConfig::new(pub_k, prv_k);
        assert_eq!(cfg.authority_pub().into_bytes(), pub_k.into_bytes());
        assert_eq!(cfg.authority_prv().into_bytes(), prv_k.into_bytes());
        assert_ne!(pub_k.into_bytes(), [0u8; 32]);
    }

    /// Pins the signature of `accept_pool_noise` against the upstream
    /// helper; the full handshake runs in the regtest e2e tests.
    #[test]
    fn accept_pool_noise_surface_type_compiles() {
        fn _assert_signature() {
            // Compile-time only.
            #[allow(dead_code)]
            async fn _example(stream: TcpStream, cfg: &NoiseConfig) {
                let _: Result<NoiseTcpStream, NoiseError> = accept_pool_noise(stream, cfg).await;
            }
        }
    }
}
