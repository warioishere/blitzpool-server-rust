// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/address/ownership/*` — prove control of a BTC address by signing a
//! server-issued challenge. An alternative to a verified email for group
//! eligibility. BIP-322 and BIP-137 recoverable signatures are both tried, so
//! the wallet's format does not matter.

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
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;

const CHALLENGE_TTL_MINUTES: i64 = 15;

pub(crate) fn routes() -> Router<SharedState> {
    Router::new()
        .route(
            // Rate-limited: 5 challenge requests per minute per client IP.
            "/api/address/ownership/challenge",
            post(challenge).layer(rate_limit::per_minute_layer(5)),
        )
        .route(
            "/api/address/ownership/verify",
            post(verify).layer(rate_limit::per_minute_layer(5)),
        )
        .route("/api/address/ownership/:address", get(by_address))
        .route("/api/address/verified/:address", get(verified_status))
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

async fn challenge(
    State(state): State<SharedState>,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let address = parse_supported_address(&body.address, state.network)?;
    let addr_str = address.as_str().to_string();

    let now = bp_common::now_ms();
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

async fn verify(
    State(state): State<SharedState>,
    Json(body): Json<VerifyBody>,
) -> Result<Json<VerifyResponse>, ApiError> {
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
    let now = bp_common::now_ms();
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

async fn by_address(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<ByAddressResponse>, ApiError> {
    let Ok(addr) = AddressId::normalized(&address) else {
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

async fn verified_status(
    State(state): State<SharedState>,
    Path(address): Path<String>,
) -> Result<Json<VerifiedStatusResponse>, ApiError> {
    let Ok(addr) = AddressId::normalized(&address) else {
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

/// `(method, script_type)` when `signature` signs `message` for `address`.
/// BIP-322 first (the only route for taproot), then BIP-137 recoverable,
/// where segwit is checked by recovering the key and re-deriving the address.
/// Shared with the custom-extranonce controller.
#[allow(clippy::collapsible_match)]
pub(crate) fn verify_message_signature(
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

/// Parse an address of the pool's network into a **canonical** `AddressId`
/// via [`AddressId::normalized`], so the ownership row is keyed exactly as
/// every verification gate looks it up.
pub(crate) fn parse_supported_address(raw: &str, network: Network) -> Result<AddressId, ApiError> {
    let trimmed = raw.trim();
    Address::from_str(trimmed)
        .ok()
        .and_then(|a| a.require_network(network).ok())
        .ok_or_else(|| ownership_error("invalid-address", StatusCode::BAD_REQUEST))?;
    AddressId::normalized(trimmed)
        .map_err(|_| ownership_error("invalid-address", StatusCode::BAD_REQUEST))
}

fn ownership_error(code: &'static str, status: StatusCode) -> ApiError {
    ApiError::GroupService { code, status }
}

pub(crate) fn random_nonce() -> String {
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

    /// A BIP-322 "simple" signature over `message`, produced by the same crate
    /// that verifies it.
    fn sign_bip322(sk: &SecretKey, address: &str, message: &str) -> String {
        let wif = bitcoin::PrivateKey::new(*sk, Network::Bitcoin).to_wif();
        bip322::sign_simple_encoded(address, message, &[wif], None).expect("bip322 signing")
    }

    // Pins the BIP-322 success path, the only route for taproot addresses.
    #[test]
    fn bip322_signature_verifies_for_segwit_and_taproot() {
        let (sk, _pk, cpk) = test_key();
        let msg = "Blitzpool address-ownership verification\nNonce: xyz";

        let p2wpkh = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(
                &p2wpkh,
                msg,
                &sign_bip322(&sk, &p2wpkh, msg),
                Network::Bitcoin
            ),
            Some(("bip322".to_string(), "p2wpkh".to_string()))
        );

        let secp = Secp256k1::new();
        let (xonly, _parity) = sk.public_key(&secp).x_only_public_key();
        let p2tr = Address::p2tr(&secp, xonly, None, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(&p2tr, msg, &sign_bip322(&sk, &p2tr, msg), Network::Bitcoin),
            Some(("bip322".to_string(), "p2tr".to_string()))
        );
    }

    // A caller-supplied witness with an uncompressed key fails verification
    // instead of panicking: the router has no `CatchPanicLayer`.
    #[test]
    fn a_crafted_witness_with_an_uncompressed_key_is_rejected_not_fatal() {
        use bitcoin::consensus::encode::serialize;
        use bitcoin::Witness;

        let (sk, _pk, cpk) = test_key();
        // P2SH-P2WPKH: the family whose verifier hashes witness[1] as a key.
        let addr = Address::p2shwpkh(&cpk, Network::Bitcoin).to_string();

        let uncompressed = bitcoin::PublicKey {
            compressed: false,
            inner: sk.public_key(&Secp256k1::new()),
        };
        assert_eq!(uncompressed.to_bytes().len(), 65, "must be uncompressed");

        // Two items, so item 1 is read as the public key.
        let mut witness = Witness::new();
        witness.push([0x30u8; 72]); // shape-only stand-in for a signature
        witness.push(uncompressed.to_bytes());

        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serialize(&witness),
        );

        assert_eq!(
            verify_message_signature(&addr, "any challenge", &signature, Network::Bitcoin),
            None,
            "a crafted witness must fail verification, not panic"
        );
    }

    #[test]
    fn bip322_signature_does_not_prove_a_different_message_or_address() {
        let (sk, _pk, cpk) = test_key();
        let addr = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();
        let sig = sign_bip322(&sk, &addr, "the real challenge");

        assert_eq!(
            verify_message_signature(&addr, "a different challenge", &sig, Network::Bitcoin),
            None
        );

        let other = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let other_cpk = CompressedPublicKey(other.public_key(&Secp256k1::new()));
        let other_addr = Address::p2wpkh(&other_cpk, Network::Bitcoin).to_string();
        assert_eq!(
            verify_message_signature(&other_addr, "the real challenge", &sig, Network::Bitcoin),
            None
        );
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
