// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/address/extranonce/*` — let an address set its own extranonce prefix
//! for one of its workers, authorised by a Bitcoin message signature.
//!
//! Flow: `challenge {address, worker, extranonce}` returns an exact message to
//! sign → the wallet signs it → `apply {address, worker, extranonce, signature}`
//! checks the signature against the STORED challenge and writes the override.
//! The stratum core picks it up at the worker's next channel-open.
//!
//! ## Why a fresh signature per change
//!
//! A `pplns_address_ownership` row only records that an address proved control
//! at some point in the past. Gating on it would let *anyone* set the prefix of
//! *any* previously-verified address — it is a fact about the address, not an
//! authentication of the caller. So every change carries its own signature, and
//! the signed message names the exact `(worker, extranonce)` it authorises: a
//! captured signature cannot be replayed for a different worker or value.
//!
//! Verification reuses
//! [`super::address_ownership::verify_message_signature`] (BIP-322 + BIP-137 /
//! Electrum) rather than a second copy of it.
//!
//! ## Reserved prefix range
//!
//! `0x00……` and `0x01……` are rejected: those are the worker partitions the SV2
//! and SV1 servers allocate from (see `bp_common::extranonce`), so a value there
//! could later be handed to another miner as well. Workers 2..=255 are unowned —
//! no allocator ever emits into them — which is what makes a hand-set prefix
//! safe to hold indefinitely. That leaves `0x02000000..=0xFFFFFFFF`, ~99% of the
//! space.

use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};

use super::address_ownership::{parse_supported_address, random_nonce, verify_message_signature};
use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;

const CHALLENGE_TTL_MINUTES: i64 = 15;

/// Top bytes the SV1/SV2 extranonce allocators own. See the module doc.
const RESERVED_TOP_BYTE_MAX: u32 = 1;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new()
        .route(
            // Rate-limited to match the ownership challenge: 5/min per client IP.
            "/api/address/extranonce/challenge",
            post(challenge::<H, M>).layer(rate_limit::per_minute_layer(5)),
        )
        .route(
            "/api/address/extranonce/apply",
            post(apply::<H, M>).layer(rate_limit::per_minute_layer(5)),
        )
}

// ─── POST /api/address/extranonce/challenge ──────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeBody {
    address: String,
    worker: String,
    /// The requested prefix as 8 hex chars, e.g. `"c0debabe"`.
    extranonce: String,
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
    let worker = normalize_worker(&body.worker);
    let prefix = parse_prefix(&body.extranonce)?;

    let now = crate::time_range::now_ms();
    let expires_at = now + CHALLENGE_TTL_MINUTES * 60 * 1000;
    let message = challenge_message(
        address.as_str(),
        &worker,
        prefix,
        &random_nonce(),
        now,
        expires_at,
    );
    bp_db::upsert_extranonce_challenge(
        &state.pool,
        &address,
        &worker,
        prefix,
        &message,
        now,
        expires_at,
    )
    .await?;
    Ok(Json(ChallengeResponse {
        message,
        expires_at,
    }))
}

// ─── POST /api/address/extranonce/apply ──────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyBody {
    address: String,
    worker: String,
    extranonce: String,
    /// Signature over the challenge message. Base64 for the recoverable
    /// (Electrum/BIP-137) formats, or the BIP-322 encoded signature.
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplyResponse {
    address: String,
    worker: String,
    /// Echoed as 8 hex chars, the same shape the request used.
    extranonce: String,
    updated_at: i64,
}

async fn apply<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<ApplyBody>,
) -> Result<Json<ApplyResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_supported_address(&body.address, state.network)?;
    let worker = normalize_worker(&body.worker);
    let prefix = parse_prefix(&body.extranonce)?;
    let signature = body.signature.trim();
    if signature.is_empty() {
        return Err(en_error("missing-signature", StatusCode::BAD_REQUEST));
    }

    let pending = bp_db::find_extranonce_challenge(&state.pool, &address)
        .await?
        .ok_or_else(|| en_error("no-challenge", StatusCode::NOT_FOUND))?;
    let now = crate::time_range::now_ms();
    if pending.expires_at < now {
        bp_db::delete_extranonce_challenge(&state.pool, &address).await?;
        return Err(en_error("challenge-expired", StatusCode::GONE));
    }

    // The signature only authorises the change the challenge was issued for.
    // Without this a valid signature for `worker-a -> X` could be replayed to
    // set `worker-b -> Y`, since both requests carry the same address.
    if pending.worker != worker || pending.prefix != prefix {
        return Err(en_error("challenge-mismatch", StatusCode::BAD_REQUEST));
    }

    // Verify against the STORED message — never a client-supplied one.
    if verify_message_signature(address.as_str(), &pending.message, signature, state.network)
        .is_none()
    {
        return Err(en_error("invalid-signature", StatusCode::BAD_REQUEST));
    }

    let saved = bp_db::upsert_custom_extranonce(&state.pool, &address, &worker, prefix, now)
        .await
        .map_err(map_prefix_conflict)?;
    // Consume the challenge.
    bp_db::delete_extranonce_challenge(&state.pool, &address).await?;
    Ok(Json(ApplyResponse {
        address: saved.address.as_str().to_string(),
        worker: saved.worker,
        extranonce: format!("{:08x}", saved.prefix),
        updated_at: saved.updated_at,
    }))
}

// ─── helpers ─────────────────────────────────────────────────────

fn challenge_message(
    address: &str,
    worker: &str,
    prefix: u32,
    nonce: &str,
    now: i64,
    expires_at: i64,
) -> String {
    // Every field the change consists of is inside the signed text, so the
    // signature authorises this exact change and nothing else. Nonce + expiry
    // stop a captured signature from being replayed later.
    format!(
        "Blitzpool extranonce change\n\
         Address: {address}\n\
         Worker: {worker}\n\
         Extranonce: {prefix:08x}\n\
         Nonce: {nonce}\n\
         Issued(ms): {now}\n\
         Expires(ms): {expires_at}"
    )
}

/// Mirror of the stratum core's worker resolution (`resolve_open_context` in
/// `bp-stratum-v2`): the worker is whatever follows the FIRST dot of
/// `user_identity`, taken verbatim, and an absent one becomes `"default"`.
///
/// Deliberately does NOT trim or lowercase: the core stores the miner's bytes
/// as-is, so the override is looked up by `(address, worker)` with a
/// case-sensitive worker. Normalising here would silently fail to match a
/// miner authorising as `Rig1` — the row would exist and never apply.
fn normalize_worker(raw: &str) -> String {
    if raw.is_empty() {
        "default".to_string()
    } else {
        raw.to_string()
    }
}

/// Parse 8 hex chars into the prefix, rejecting the allocator-owned range.
fn parse_prefix(raw: &str) -> Result<u32, ApiError> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() != 8 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(en_error("invalid-extranonce", StatusCode::BAD_REQUEST));
    }
    let prefix = u32::from_str_radix(hex, 16)
        .map_err(|_| en_error("invalid-extranonce", StatusCode::BAD_REQUEST))?;
    if prefix >> 24 <= RESERVED_TOP_BYTE_MAX {
        return Err(en_error(
            "reserved-extranonce-range",
            StatusCode::BAD_REQUEST,
        ));
    }
    Ok(prefix)
}

/// The `UNIQUE (address, prefix)` violation is a user error, not a 500: this
/// address already points another worker at that prefix, which in Solo would
/// have both workers grinding one search space (same payouts -> same coinbase).
///
/// Matched on the constraint NAME, not just SQLSTATE `23505`: the upsert's
/// `ON CONFLICT (address, worker)` already absorbs the PK collision, so the
/// only unique violation that can surface here is the prefix one — but keying
/// on the name keeps that precise if another constraint is ever added. Verified
/// against live PG that sqlx populates `.constraint()` with this exact name.
fn map_prefix_conflict(err: bp_db::DbError) -> ApiError {
    if let bp_db::DbError::Sqlx(sqlx::Error::Database(ref db_err)) = err {
        if db_err.code().as_deref() == Some("23505")
            && db_err.constraint() == Some("pplns_custom_extranonce_address_prefix_key")
        {
            return en_error("extranonce-in-use", StatusCode::CONFLICT);
        }
    }
    ApiError::from(err)
}

fn en_error(code: &'static str, status: StatusCode) -> ApiError {
    ApiError::GroupService { code, status }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sign_message::{signed_msg_hash, MessageSignature};
    use bitcoin::{Address, CompressedPublicKey, Network};

    // A real recoverable "Bitcoin Signed Message" signature over `message`,
    // base64 — the exact shape a wallet returns. Mirrors the ownership test's
    // helper so this exercises the same verification the API runs.
    fn sign_recoverable(sk: &SecretKey, message: &str) -> String {
        let secp = Secp256k1::new();
        let hash = signed_msg_hash(message);
        let msg = Message::from_digest(hash.to_byte_array());
        let rec = secp.sign_ecdsa_recoverable(&msg, sk);
        MessageSignature::new(rec, true).to_base64()
    }

    /// End-to-end auth of one change: build the controller's own challenge
    /// message, sign it for real, and confirm `verify_message_signature`
    /// accepts it. Guards against the message format drifting out of sync with
    /// what actually gets signed — a mismatch there would make every apply fail
    /// with `invalid-signature`, which no amount of helper unit-testing catches.
    #[test]
    fn signed_challenge_message_verifies() {
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let cpk = CompressedPublicKey(sk.public_key(&Secp256k1::new()));
        let addr = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();

        let msg = challenge_message(&addr, "rig1", 0xc0de_babe, "nonce123", 1000, 2000);
        let sig = sign_recoverable(&sk, &msg);

        assert!(
            verify_message_signature(&addr, &msg, &sig, Network::Bitcoin).is_some(),
            "a genuine signature over the controller's challenge message must verify"
        );
        // A signature over a DIFFERENT change (other prefix) must not verify
        // against this message — the on-chain guarantee behind the apply-time
        // worker+prefix re-check.
        let other = challenge_message(&addr, "rig1", 0xdead_beef, "nonce123", 1000, 2000);
        let other_sig = sign_recoverable(&sk, &other);
        assert!(
            verify_message_signature(&addr, &msg, &other_sig, Network::Bitcoin).is_none(),
            "a signature over a different change must not verify against this message"
        );
    }

    #[test]
    fn parse_prefix_accepts_the_unowned_range() {
        assert_eq!(parse_prefix("02000000").unwrap(), 0x0200_0000);
        assert_eq!(parse_prefix("c0debabe").unwrap(), 0xc0de_babe);
        assert_eq!(parse_prefix("ffffffff").unwrap(), 0xffff_ffff);
        // Case-insensitive + optional 0x, since operators paste both shapes.
        assert_eq!(parse_prefix("0xC0DEBABE").unwrap(), 0xc0de_babe);
        assert_eq!(parse_prefix("  c0debabe  ").unwrap(), 0xc0de_babe);
    }

    /// The SV2 allocator emits `0x00……` and the SV1 one `0x01……`, so a prefix
    /// there could be handed to another miner too.
    #[test]
    fn parse_prefix_rejects_the_allocator_owned_range() {
        for raw in ["00000000", "00ffffff", "01000000", "01abcdef", "01ffffff"] {
            let err = parse_prefix(raw).unwrap_err();
            assert!(
                matches!(
                    err,
                    ApiError::GroupService {
                        code: "reserved-extranonce-range",
                        ..
                    }
                ),
                "{raw} must be rejected as reserved, got {err:?}"
            );
        }
        // One byte up is the first settable value.
        assert!(parse_prefix("02000000").is_ok());
    }

    #[test]
    fn parse_prefix_rejects_malformed_input() {
        for raw in ["", "c0debab", "c0debabee", "zzzzzzzz", "0x", "1234567g"] {
            assert!(
                matches!(
                    parse_prefix(raw),
                    Err(ApiError::GroupService {
                        code: "invalid-extranonce",
                        ..
                    })
                ),
                "{raw} must be rejected as malformed"
            );
        }
    }

    /// Pins the mirror of the core's rule — an absent worker is `default`
    /// there, and anything else is taken verbatim (case included).
    #[test]
    fn normalize_worker_mirrors_the_core() {
        assert_eq!(normalize_worker(""), "default");
        assert_eq!(normalize_worker("Rig1"), "Rig1");
        assert_eq!(normalize_worker("rig.1"), "rig.1");
        assert_eq!(normalize_worker(" spaced "), " spaced ");
    }

    /// The signed text must name every field of the change; the apply handler
    /// re-checks worker+prefix against the stored challenge on top of this.
    #[test]
    fn challenge_message_binds_address_worker_and_prefix() {
        let msg = challenge_message("bc1qexample", "rig1", 0xc0de_babe, "nonce123", 1000, 2000);
        assert!(msg.contains("Address: bc1qexample"));
        assert!(msg.contains("Worker: rig1"));
        assert!(msg.contains("Extranonce: c0debabe"));
        assert!(msg.contains("Nonce: nonce123"));
        assert!(msg.contains("Issued(ms): 1000"));
        assert!(msg.contains("Expires(ms): 2000"));
    }

    /// A different worker or prefix must produce a different message — else one
    /// signature would authorise more than the change it was issued for.
    #[test]
    fn challenge_message_differs_per_change() {
        let base = challenge_message("bc1qexample", "rig1", 0xc0de_babe, "n", 1, 2);
        let other_worker = challenge_message("bc1qexample", "rig2", 0xc0de_babe, "n", 1, 2);
        let other_prefix = challenge_message("bc1qexample", "rig1", 0xdead_beef, "n", 1, 2);
        assert_ne!(base, other_worker);
        assert_ne!(base, other_prefix);
    }
}
