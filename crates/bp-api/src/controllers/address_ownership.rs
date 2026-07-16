// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/address/ownership/*` — prove control of a BTC address by signing a
//! server-issued challenge with the address's key.
//!
//! A generic "this address proved control" primitive (a 2nd equivalent option
//! to the verified-email binding for group-invite eligibility, and — later —
//! the auth gate for the custom-extranonce override).
//!
//! Flow: `challenge {address}` returns an exact message to sign → the wallet
//! signs it (Sparrow/Electrum text-paste, or a hardware wallet) → `verify
//! {address, signature}` checks the signature against the stored challenge and
//! records the verified binding.
//!
//! Signature families accepted (the server tries each, so the user's wallet /
//! Sparrow format is irrelevant):
//!   - BIP-322 (`bip322` crate) — covers taproot `bc1p…` + segwit.
//!   - Legacy / Electrum / BIP-137 recoverable signatures (`bitcoin::sign_message`)
//!     — note `is_signed_by_address` only supports P2PKH, so segwit is verified by
//!     recovering the pubkey and re-deriving the address.

use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use base64::Engine;
use bitcoin::{
    address::AddressType,
    secp256k1::Secp256k1,
    sign_message::{signed_msg_hash, MessageSignature},
    Address, CompressedPublicKey, Network,
};
use bp_common::AddressId;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;

const CHALLENGE_TTL_MINUTES: i64 = 15;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route(
            // Rate-limited: 5 challenge requests per minute per client IP.
            "/api/address/ownership/challenge",
            post(challenge::<H, M>).layer(rate_limit::per_minute_layer(5)),
        )
        .route(
            "/api/address/ownership/verify",
            post(verify::<H, M>).layer(rate_limit::per_minute_layer(5)),
        )
        .route("/api/address/ownership/:address", get(by_address::<H, M>))
        .route(
            "/api/address/verified/:address",
            get(verified_status::<H, M>),
        )
}

// ─── POST /api/address/ownership/challenge ───────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeBody {
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    /// The exact UTF-8 message the wallet must sign.
    message: String,
    expires_at: i64,
}

async fn challenge<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<ChallengeResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_supported_address(&body.address, state.network)?;
    let addr_str = address.as_str().to_string();

    let now = crate::time_range::now_ms();
    let expires_at = now + CHALLENGE_TTL_MINUTES * 60 * 1000;
    let nonce = random_nonce();
    // Human-readable + bound to the address, a nonce and an expiry so a captured
    // signature can't be replayed for a different address or after expiry.
    let message = format!(
        "Blitzpool address-ownership verification\n\
         Address: {addr_str}\n\
         Nonce: {nonce}\n\
         Issued(ms): {now}\n\
         Expires(ms): {expires_at}"
    );
    bp_db::upsert_ownership_challenge(&state.pool, &address, &message, now, expires_at).await?;
    Ok(Json(ChallengeResponse {
        message,
        expires_at,
    }))
}

// ─── POST /api/address/ownership/verify ──────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBody {
    address: String,
    /// The signature over the challenge message. Base64 for the recoverable
    /// (Electrum/BIP-137) formats, or the BIP-322 encoded signature.
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    address: String,
    method: String,
    script_type: String,
    verified_at: i64,
}

async fn verify<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<VerifyBody>,
) -> Result<Json<VerifyResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_supported_address(&body.address, state.network)?;
    let signature = body.signature.trim();
    if signature.is_empty() {
        return Err(ownership_error(
            "missing-signature",
            StatusCode::BAD_REQUEST,
        ));
    }

    let pending = bp_db::find_ownership_challenge(&state.pool, &address)
        .await?
        .ok_or_else(|| ownership_error("no-challenge", StatusCode::NOT_FOUND))?;
    let now = crate::time_range::now_ms();
    if pending.expires_at < now {
        bp_db::delete_ownership_challenge(&state.pool, &address).await?;
        return Err(ownership_error("challenge-expired", StatusCode::GONE));
    }

    // Verify against the STORED challenge message — never a client-supplied one.
    let Some((method, script_type)) =
        verify_message_signature(address.as_str(), &pending.message, signature, state.network)
    else {
        return Err(ownership_error(
            "invalid-signature",
            StatusCode::BAD_REQUEST,
        ));
    };

    let saved =
        bp_db::upsert_address_ownership_verified(&state.pool, &address, &method, &script_type, now)
            .await?;
    // Consume the challenge.
    bp_db::delete_ownership_challenge(&state.pool, &address).await?;
    Ok(Json(VerifyResponse {
        address: saved.address.as_str().to_string(),
        method: saved.method,
        script_type: saved.script_type,
        verified_at: saved.verified_at,
    }))
}

// ─── GET /api/address/ownership/:address ─────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ByAddressResponse {
    verified: bool,
    method: Option<String>,
    script_type: Option<String>,
    verified_at: Option<i64>,
}

async fn by_address<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<ByAddressResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let Ok(addr) = AddressId::new(bp_mining_job::normalize_btc_address(&address)) else {
        return Ok(Json(ByAddressResponse {
            verified: false,
            method: None,
            script_type: None,
            verified_at: None,
        }));
    };
    match bp_db::find_address_ownership(&state.pool, &addr).await? {
        Some(row) => Ok(Json(ByAddressResponse {
            verified: true,
            method: Some(row.method),
            script_type: Some(row.script_type),
            verified_at: Some(row.verified_at),
        })),
        None => Ok(Json(ByAddressResponse {
            verified: false,
            method: None,
            script_type: None,
            verified_at: None,
        })),
    }
}

// ─── GET /api/address/verified/:address ──────────────────────────
// The unified onboarding gate status: is this address verified by email OR by a
// signature ownership proof? Drives the shared "verify your address" UI.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedStatusResponse {
    verified: bool,
    email_verified: bool,
    signature_verified: bool,
}

async fn verified_status<H, M>(
    State(state): State<SharedState<H, M>>,
    Path(address): Path<String>,
) -> Result<Json<VerifiedStatusResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let Ok(addr) = AddressId::new(bp_mining_job::normalize_btc_address(&address)) else {
        return Ok(Json(VerifiedStatusResponse {
            verified: false,
            email_verified: false,
            signature_verified: false,
        }));
    };
    let email_verified = bp_db::find_address_email(&state.pool, &addr)
        .await?
        .and_then(|b| b.verified_at)
        .is_some();
    let signature_verified = bp_db::is_address_ownership_verified(&state.pool, &addr).await?;
    Ok(Json(VerifiedStatusResponse {
        verified: email_verified || signature_verified,
        email_verified,
        signature_verified,
    }))
}

// ─── signature verification ──────────────────────────────────────

/// Verify `signature` signs `message` for `address`. Returns `(method,
/// script_type)` on success. Tries BIP-322 first (covers every type incl.
/// taproot), then the legacy/Electrum/BIP-137 recoverable path.
// The per-address-type `match` arms each run a distinct verification (recover +
// re-derive + compare) — keeping the explicit `if` inside each arm is clearer
// for security review than collapsing into match guards, so allow the lint.
#[allow(clippy::collapsible_match)]
fn verify_message_signature(
    address: &str,
    message: &str,
    signature: &str,
    network: Network,
) -> Option<(String, String)> {
    let addr = Address::from_str(address)
        .ok()?
        .require_network(network)
        .ok()?;
    let script_type = script_type_label(addr.address_type()?);

    // 1) BIP-322 (any address type, incl. taproot).
    if bip322::verify_simple_encoded(address, message, signature).is_ok() {
        return Some(("bip322".to_string(), script_type.to_string()));
    }

    // 2) Legacy / Electrum / BIP-137 recoverable signature (base64).
    let sig = MessageSignature::from_base64(signature).ok()?;
    let msg_hash = signed_msg_hash(message);
    let secp = Secp256k1::verification_only();
    match addr.address_type()? {
        AddressType::P2pkh => {
            if sig
                .is_signed_by_address(&secp, &addr, msg_hash)
                .unwrap_or(false)
            {
                return Some(("bip137".to_string(), "p2pkh".to_string()));
            }
        }
        AddressType::P2wpkh => {
            let pk = sig.recover_pubkey(&secp, msg_hash).ok()?;
            let cpk = CompressedPublicKey::try_from(pk).ok()?;
            let derived = Address::p2wpkh(&cpk, network);
            if derived == addr {
                return Some(("bip137".to_string(), "p2wpkh".to_string()));
            }
        }
        AddressType::P2sh => {
            // Wrapped segwit (p2sh-p2wpkh): recover + re-derive + compare.
            let pk = sig.recover_pubkey(&secp, msg_hash).ok()?;
            let cpk = CompressedPublicKey::try_from(pk).ok()?;
            let derived = Address::p2shwpkh(&cpk, network);
            if derived == addr {
                return Some(("bip137".to_string(), "p2sh-p2wpkh".to_string()));
            }
        }
        _ => {}
    }
    None
}

fn script_type_label(t: AddressType) -> &'static str {
    match t {
        AddressType::P2pkh => "p2pkh",
        AddressType::P2sh => "p2sh-p2wpkh",
        AddressType::P2wpkh => "p2wpkh",
        AddressType::P2wsh => "p2wsh",
        AddressType::P2tr => "p2tr",
        _ => "unknown",
    }
}

// ─── helpers ─────────────────────────────────────────────────────

/// Parse + validate a mainnet BTC address into a **canonical** `AddressId`.
/// Rejects testnet / malformed addresses at the API boundary, then normalises
/// via the single source of truth [`bp_mining_job::normalize_btc_address`]
/// (lowercase bech32, preserve case-sensitive Base58) so the ownership row is
/// keyed identically to what every verification gate looks up — otherwise a
/// mixed-case Base58 (or upper-case bech32) proof would never match.
fn parse_supported_address(raw: &str, network: Network) -> Result<AddressId, ApiError> {
    let trimmed = raw.trim();
    Address::from_str(trimmed)
        .ok()
        .and_then(|a| a.require_network(network).ok())
        .ok_or_else(|| ownership_error("invalid-address", StatusCode::BAD_REQUEST))?;
    AddressId::new(bp_mining_job::normalize_btc_address(trimmed))
        .map_err(|_| ownership_error("invalid-address", StatusCode::BAD_REQUEST))
}

fn ownership_error(code: &'static str, status: StatusCode) -> ApiError {
    ApiError::GroupService { code, status }
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Message, SecretKey};
    use bitcoin::PublicKey;

    // A single recoverable "Bitcoin Signed Message" signature (the Electrum /
    // BIP-137 wire format) over `message`, base64-encoded — exactly what a wallet
    // hands back for a legacy/segwit address.
    fn sign_recoverable(sk: &SecretKey, message: &str) -> String {
        let secp = Secp256k1::new();
        let hash = signed_msg_hash(message);
        let msg = Message::from_digest(hash.to_byte_array());
        let rec = secp.sign_ecdsa_recoverable(&msg, sk);
        MessageSignature::new(rec, true).to_base64()
    }

    fn test_key() -> (SecretKey, PublicKey, CompressedPublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let inner = sk.public_key(&secp);
        (sk, PublicKey::new(inner), CompressedPublicKey(inner))
    }

    #[test]
    fn recoverable_signature_verifies_across_p2pkh_p2wpkh_p2sh() {
        let (sk, pk, cpk) = test_key();
        let msg = "Blitzpool address-ownership verification\nNonce: abc";
        let sig = sign_recoverable(&sk, msg);

        // The same recoverable signature proves control of every address type
        // derived from the key — the verifier recovers the pubkey and re-derives.
        let p2pkh = Address::p2pkh(pk, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(&p2pkh, msg, &sig, Network::Bitcoin),
            Some(("bip137".to_string(), "p2pkh".to_string()))
        );

        let p2wpkh = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(&p2wpkh, msg, &sig, Network::Bitcoin),
            Some(("bip137".to_string(), "p2wpkh".to_string()))
        );

        let p2sh = Address::p2shwpkh(&cpk, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(&p2sh, msg, &sig, Network::Bitcoin),
            Some(("bip137".to_string(), "p2sh-p2wpkh".to_string()))
        );
    }

    #[test]
    fn rejects_wrong_message_wrong_address_and_garbage() {
        let (sk, _pk, cpk) = test_key();
        let msg = "the real challenge";
        let sig = sign_recoverable(&sk, msg);
        let addr = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();

        // Right sig, wrong message → recovers a different key → no match.
        assert_eq!(
            verify_message_signature(&addr, "a different message", &sig, Network::Bitcoin),
            None
        );

        // Right sig+message, but a different address (different key) → no match.
        let other_sk = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let other_cpk = CompressedPublicKey(other_sk.public_key(&Secp256k1::new()));
        let other_addr = Address::p2wpkh(&other_cpk, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(&other_addr, msg, &sig, Network::Bitcoin),
            None
        );

        // Garbage signature → None, not a panic.
        assert_eq!(
            verify_message_signature(&addr, msg, "not-a-signature", Network::Bitcoin),
            None
        );
    }
}
