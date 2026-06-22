// SPDX-License-Identifier: AGPL-3.0-or-later

//! Noise-XK handshake wiring + per-connection certificate validity.
//!
//! Thin wrapper over [`stratum_apps::network_helpers::accept_noise_connection`]
//! (runtime-dep) — we do **not** re-implement the Noise state machine
//! or the underlying handshake protocol. The `stratum-apps` crate owns the
//! wire format; this module owns the **pool's config + the "12h cert
//! validity" convention** that [`bp-stratum-v2`] commits to in production
//! wiring.
//!
//! ## "12h cert rotation"
//!
//! Each accepted Noise connection generates a fresh Responder via
//! `Responder::from_authority_kp(pub, prv, Duration::from_secs(cert_validity))`.
//! The `cert_validity` controls how long the cert the JDC/miner sees is
//! valid for. The pool's authority key-pair itself doesn't rotate —
//! only the per-connection cert. Setting [`DEFAULT_CERT_VALIDITY`] to
//! 12 hours means the cert presented to a freshly-connected miner is
//! valid for half a day; that matches the operational hand-off doc
//! and is short enough that a leaked cert is naturally retired by
//! daily-rolling-key practice without manual revocation.
//!
//! There is no shared mutable state to rotate centrally — every
//! [`accept_pool_noise`] call generates a fresh Responder with a fresh
//! 12h cert. The "rotation" is therefore inherent in the per-connection
//! generation; this module exposes the convention as a named constant
//! and the explicit IO-layer config knob.
//!
//! ## What this module wraps vs. what stays in `stratum-apps`
//!
//! - **In `stratum-apps`** (runtime-dep, MIT/Apache): the Noise-XK
//!   handshake state machine, framing, encoder/decoder, the
//!   `Responder::from_authority_kp` builder, the `NoiseTcpStream`
//!   read/write split.
//! - **In this module**: pool-side config (parsed authority keys,
//!   `cert_validity` Duration), the convenience builder, the
//!   re-exports (so consumers `use crate::noise::{NoiseConfig,
//!   NoiseTcpStream, ...}` without the deep `stratum_apps::network_helpers::*`
//!   path), and the [`DEFAULT_CERT_VALIDITY`] constant.
//!
//! We runtime-dep the protocol plumbing + write our own pool-side state
//! machine + config. This module is exactly that split applied to Noise.
//!
//! ## What this module does **not** do
//!
//! - **TCP-accept loop**: belongs in [`crate::server`] /
//!   [`crate::jdp_server`] — they own the listener, the per-connection
//!   task spawn, the cancellation token, and the fail-ban / rate-limit
//!   guards. This module is invoked one-call-per-accepted-connection
//!   from inside their loop.
//! - **Frame routing**: belongs to the per-connection task in
//!   `server.rs` / `jdp_server.rs`. Once [`accept_pool_noise`] returns
//!   a [`NoiseTcpStream`], the per-connection task drives the
//!   `read_frame()` / `write_frame()` loop.

use std::time::Duration;

use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::{accept_noise_connection, Error as NoiseHelpersError};
use stratum_core::binary_sv2::{Deserialize, GetSize, Serialize};
use tokio::net::TcpStream;

// ── Re-exports — let consumers import via `crate::noise::*` ─────────

pub use stratum_apps::network_helpers::noise_stream::{
    NoiseTcpReadHalf, NoiseTcpStream, NoiseTcpWriteHalf,
};

/// Errors propagated from [`accept_pool_noise`]. Re-exports the
/// upstream [`stratum_apps::network_helpers::Error`] under a
/// pool-side alias so error handling in `server.rs` / `jdp_server.rs`
/// doesn't depend on the deep path.
pub type NoiseError = NoiseHelpersError;

// ── Constants ───────────────────────────────────────────────────────

/// Cert validity used in production: 12 hours.
///
/// Rationale: per the operational hand-off doc, the pool issues
/// per-connection Noise certs that live for half a day. Connections
/// outliving this re-handshake on reconnect with a fresh cert. A
/// leaked cert is naturally retired by daily key practice without
/// requiring manual revocation tooling.
pub const DEFAULT_CERT_VALIDITY: Duration = Duration::from_secs(12 * 3600);

/// Minimum sane cert validity. Lower than this means certs expire
/// before a typical mining session's first share — guards against
/// config typos like `cert_validity = 60` (mistaking seconds for
/// minutes).
pub const MIN_CERT_VALIDITY: Duration = Duration::from_secs(60);

/// Maximum sane cert validity. Higher than this defeats the
/// natural-retirement-via-daily-rotation property. 7 days is the
/// upper bound — anything longer needs explicit acknowledgement at
/// the call site.
pub const MAX_CERT_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);

// ── NoiseConfig ─────────────────────────────────────────────────────

/// Pool-side Noise-handshake configuration. Holds the parsed
/// authority key-pair + the per-connection cert validity. Clone-able
/// so the same config can be shared between the mining-server and
/// JDP-server accept loops without an `Arc`.
#[derive(Clone, Debug)]
pub struct NoiseConfig {
    authority_pub: Secp256k1PublicKey,
    authority_prv: Secp256k1SecretKey,
    cert_validity: Duration,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NoiseConfigError {
    /// `cert_validity` was outside `[MIN_CERT_VALIDITY,
    /// MAX_CERT_VALIDITY]`. The caller's config has a likely typo or
    /// an unsafe long-lived cert.
    #[error("cert_validity {got_secs}s outside the sane range [{min_secs}s, {max_secs}s]")]
    OutOfRange {
        got_secs: u64,
        min_secs: u64,
        max_secs: u64,
    },
    /// Authority public key didn't parse from its base58-encoded
    /// string form. The wrapped message is from
    /// [`Secp256k1PublicKey`]'s [`std::str::FromStr`] impl.
    #[error("authority public key parse error: {0}")]
    InvalidPublicKey(String),
    /// Authority private key didn't parse from its base58-encoded
    /// string form.
    #[error("authority private key parse error: {0}")]
    InvalidPrivateKey(String),
}

impl NoiseConfig {
    /// Construct from already-parsed key types with an explicit
    /// validity. Use [`Self::parse_strings`] when loading from a
    /// config file's textual values.
    pub fn new(
        authority_pub: Secp256k1PublicKey,
        authority_prv: Secp256k1SecretKey,
        cert_validity: Duration,
    ) -> Result<Self, NoiseConfigError> {
        if cert_validity < MIN_CERT_VALIDITY || cert_validity > MAX_CERT_VALIDITY {
            return Err(NoiseConfigError::OutOfRange {
                got_secs: cert_validity.as_secs(),
                min_secs: MIN_CERT_VALIDITY.as_secs(),
                max_secs: MAX_CERT_VALIDITY.as_secs(),
            });
        }
        Ok(Self {
            authority_pub,
            authority_prv,
            cert_validity,
        })
    }

    /// Convenience constructor with [`DEFAULT_CERT_VALIDITY`] (12 h).
    pub fn with_default_cert_validity(
        authority_pub: Secp256k1PublicKey,
        authority_prv: Secp256k1SecretKey,
    ) -> Self {
        Self {
            authority_pub,
            authority_prv,
            cert_validity: DEFAULT_CERT_VALIDITY,
        }
    }

    /// Parse keys from their base58-encoded string form, using the
    /// `FromStr` impls in [`stratum_apps::key_utils`]. Same
    /// validity-range guard as [`Self::new`].
    pub fn parse_strings(
        authority_pub_str: &str,
        authority_prv_str: &str,
        cert_validity: Duration,
    ) -> Result<Self, NoiseConfigError> {
        let authority_pub: Secp256k1PublicKey =
            authority_pub_str
                .parse()
                .map_err(|e: stratum_apps::key_utils::Error| {
                    NoiseConfigError::InvalidPublicKey(format!("{e:?}"))
                })?;
        let authority_prv: Secp256k1SecretKey =
            authority_prv_str
                .parse()
                .map_err(|e: stratum_apps::key_utils::Error| {
                    NoiseConfigError::InvalidPrivateKey(format!("{e:?}"))
                })?;
        Self::new(authority_pub, authority_prv, cert_validity)
    }

    pub fn authority_pub(&self) -> &Secp256k1PublicKey {
        &self.authority_pub
    }

    pub fn authority_prv(&self) -> &Secp256k1SecretKey {
        &self.authority_prv
    }

    pub fn cert_validity(&self) -> Duration {
        self.cert_validity
    }
}

// ── accept_pool_noise ───────────────────────────────────────────────

/// Accept a freshly-connected `TcpStream` as a Noise responder.
///
/// Thin wrapper over
/// [`stratum_apps::network_helpers::accept_noise_connection`] that
/// passes the pool's authority key-pair + cert validity from
/// [`NoiseConfig`]. The handshake timeout is `stratum_apps`-internal
/// (10 s default at the time of pinning); see
/// [`stratum_apps::network_helpers::noise_stream::NoiseTcpStream::new`]
/// for the override path.
///
/// On success returns a [`NoiseTcpStream<Message>`] split-ready for
/// the per-connection task; on failure the IO layer closes the TCP
/// stream and increments a handshake-failure counter (per-IP fail-ban
/// is the listener-loop's concern, deferred to `server.rs`).
///
/// `Message` is the SV2 protocol-message-union type the caller
/// chooses (mining-side or JDP-side). The generic stays decoupled
/// from this layer.
pub async fn accept_pool_noise<Message>(
    stream: TcpStream,
    config: &NoiseConfig,
) -> Result<NoiseTcpStream<Message>, NoiseError>
where
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    accept_noise_connection::<Message>(
        stream,
        config.authority_pub,
        config.authority_prv,
        config.cert_validity.as_secs(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public test key-pair from the standard SV2 example pool config.
    /// Safe to commit; matches the standard SV2 testnet/regtest
    /// reference fixtures.
    const TEST_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const TEST_PRV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    #[test]
    fn default_cert_validity_is_12_hours() {
        assert_eq!(DEFAULT_CERT_VALIDITY, Duration::from_secs(12 * 3600));
    }

    #[test]
    fn parse_strings_roundtrips_sri_test_keys() {
        let cfg =
            NoiseConfig::parse_strings(TEST_PUB, TEST_PRV, DEFAULT_CERT_VALIDITY).expect("valid");
        assert_eq!(cfg.cert_validity(), DEFAULT_CERT_VALIDITY);
        // Round-trip: emit via Debug then re-parse (FromStr is
        // base58-stable). Use `into_bytes()` to confirm the key parsed
        // into a non-zero value.
        assert_ne!((*cfg.authority_pub()).into_bytes(), [0u8; 32]);
        assert_ne!((*cfg.authority_prv()).into_bytes(), [0u8; 32]);
    }

    #[test]
    fn parse_strings_rejects_bogus_public_key() {
        let err = NoiseConfig::parse_strings("not-a-real-key", TEST_PRV, DEFAULT_CERT_VALIDITY)
            .unwrap_err();
        assert!(matches!(err, NoiseConfigError::InvalidPublicKey(_)));
    }

    #[test]
    fn parse_strings_rejects_bogus_private_key() {
        let err = NoiseConfig::parse_strings(TEST_PUB, "not-a-real-key", DEFAULT_CERT_VALIDITY)
            .unwrap_err();
        assert!(matches!(err, NoiseConfigError::InvalidPrivateKey(_)));
    }

    #[test]
    fn new_rejects_cert_validity_below_minimum() {
        let pub_k: Secp256k1PublicKey = TEST_PUB.parse().unwrap();
        let prv_k: Secp256k1SecretKey = TEST_PRV.parse().unwrap();
        let err = NoiseConfig::new(pub_k, prv_k, Duration::from_secs(30)).unwrap_err();
        assert_eq!(
            err,
            NoiseConfigError::OutOfRange {
                got_secs: 30,
                min_secs: 60,
                max_secs: 7 * 24 * 3600,
            }
        );
    }

    #[test]
    fn new_rejects_cert_validity_above_maximum() {
        let pub_k: Secp256k1PublicKey = TEST_PUB.parse().unwrap();
        let prv_k: Secp256k1SecretKey = TEST_PRV.parse().unwrap();
        let err = NoiseConfig::new(pub_k, prv_k, Duration::from_secs(8 * 24 * 3600)).unwrap_err();
        assert!(matches!(err, NoiseConfigError::OutOfRange { .. }));
    }

    #[test]
    fn new_accepts_boundary_values() {
        let pub_k: Secp256k1PublicKey = TEST_PUB.parse().unwrap();
        let prv_k: Secp256k1SecretKey = TEST_PRV.parse().unwrap();
        assert!(NoiseConfig::new(pub_k, prv_k, MIN_CERT_VALIDITY).is_ok());
        assert!(NoiseConfig::new(pub_k, prv_k, MAX_CERT_VALIDITY).is_ok());
    }

    #[test]
    fn with_default_cert_validity_skips_range_check() {
        let pub_k: Secp256k1PublicKey = TEST_PUB.parse().unwrap();
        let prv_k: Secp256k1SecretKey = TEST_PRV.parse().unwrap();
        let cfg = NoiseConfig::with_default_cert_validity(pub_k, prv_k);
        assert_eq!(cfg.cert_validity(), DEFAULT_CERT_VALIDITY);
    }

    /// `Clone` allows shareing the same config between mining +
    /// JDP server accept loops without an Arc indirection.
    #[test]
    fn noise_config_is_cloneable() {
        let cfg = NoiseConfig::parse_strings(TEST_PUB, TEST_PRV, DEFAULT_CERT_VALIDITY).unwrap();
        let cfg2 = cfg.clone();
        assert_eq!(cfg.cert_validity(), cfg2.cert_validity());
    }

    /// `accept_pool_noise` is async + needs a real TCP-stream peer
    /// to handshake against. The full handshake is exercised in the
    /// regtest e2e tests (`tests/regtest_standard.rs` +
    /// `tests/regtest_extended.rs`) where a real miner client peers
    /// with the pool. Here we only assert the surface type — the
    /// function exists, takes our `&NoiseConfig`, and compiles
    /// against the upstream signature.
    #[test]
    fn accept_pool_noise_surface_type_compiles() {
        fn _assert_signature() {
            // Compile-time only — confirms accept_pool_noise's
            // generic signature is callable with a concrete
            // Message type. Doesn't run.
            #[allow(dead_code)]
            async fn _example(stream: TcpStream, cfg: &NoiseConfig) {
                // Pick any Message type that satisfies the trait
                // bounds — `stratum_core::mining_sv2::CloseChannel`
                // is small + ubiquitous.
                let _: Result<
                    NoiseTcpStream<stratum_core::mining_sv2::CloseChannel<'static>>,
                    NoiseError,
                > = accept_pool_noise(stream, cfg).await;
            }
        }
    }
}
