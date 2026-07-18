// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/address/extranonce/*` — let a Solo address set its own extranonce
//! prefix per worker, authorised by a stored bearer **token**.
//!
//! Flow:
//! 1. `challenge {address}` → an exact message to sign (nonced, 15-min TTL).
//! 2. sign it with the address key → `token {address, signature}` verifies the
//!    signature and returns a random **token** (only its hash is stored). The
//!    signature is one-time; the token is the reusable credential.
//! 3. `set {address, worker, extranonce, token}` — a headless, no-UI call that
//!    presents the token and sets the prefix for that worker. Repeat per worker
//!    / per change with the same token.
//!
//! The feature is Solo-only and cannot move money (the coinbase still pays the
//! address), so a long-lived token is an acceptable, low-stakes credential. Its
//! only powers are: set a custom extranonce prefix on the address's own Solo
//! workers. Re-issuing (a fresh sign) rotates the token, revoking the old one.
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
use bp_common::AddressId;
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

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
            "/api/address/extranonce/token",
            post(token::<H, M>).layer(rate_limit::per_minute_layer(5)),
        )
        .route(
            "/api/address/extranonce/set",
            post(set::<H, M>).layer(rate_limit::per_minute_layer(30)),
        )
}

// ─── POST /api/address/extranonce/challenge ──────────────────────

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
    // Reject non-Solo addresses up front so a customer isn't handed a message to
    // sign for a token that could never set a (Solo-only) override.
    ensure_solo_eligible(&state.pool, state.pplns.as_deref(), &address).await?;

    let now = crate::time_range::now_ms();
    let expires_at = now + CHALLENGE_TTL_MINUTES * 60 * 1000;
    let message = challenge_message(address.as_str(), &random_nonce(), now, expires_at);
    bp_db::upsert_extranonce_challenge(&state.pool, &address, &message, now, expires_at).await?;
    Ok(Json(ChallengeResponse {
        message,
        expires_at,
    }))
}

// ─── POST /api/address/extranonce/token ──────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenBody {
    address: String,
    /// Signature over the challenge message. Base64 for the recoverable
    /// (Electrum/BIP-137) formats, or the BIP-322 encoded signature.
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    address: String,
    /// The bearer token to present on every `set` call. Store it — only its
    /// hash is kept server-side, so it can't be recovered later.
    token: String,
    created_at: i64,
}

async fn token<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<TokenBody>,
) -> Result<Json<TokenResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_supported_address(&body.address, state.network)?;
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

    // Verify against the STORED message — never a client-supplied one.
    if verify_message_signature(address.as_str(), &pending.message, signature, state.network)
        .is_none()
    {
        return Err(en_error("invalid-signature", StatusCode::BAD_REQUEST));
    }

    // Issue a fresh token, store only its hash (overwriting/revoking any prior
    // one), and consume the challenge so the signature can't be replayed.
    let token = random_token();
    bp_db::upsert_extranonce_token(&state.pool, &address, &sha256_hex(&token), now).await?;
    bp_db::delete_extranonce_challenge(&state.pool, &address).await?;
    Ok(Json(TokenResponse {
        address: address.as_str().to_string(),
        token,
        created_at: now,
    }))
}

// ─── POST /api/address/extranonce/set ────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetBody {
    address: String,
    worker: String,
    extranonce: String,
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetResponse {
    address: String,
    worker: String,
    /// Echoed as 8 hex chars, the same shape the request used.
    extranonce: String,
    updated_at: i64,
}

async fn set<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(body): Json<SetBody>,
) -> Result<Json<SetResponse>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let address = parse_supported_address(&body.address, state.network)?;
    let worker = normalize_worker(&body.worker);
    let prefix = parse_prefix(&body.extranonce)?;
    ensure_solo_eligible(&state.pool, state.pplns.as_deref(), &address).await?;

    verify_token(&state.pool, &address, &body.token).await?;

    let now = crate::time_range::now_ms();
    let saved = bp_db::upsert_custom_extranonce(&state.pool, &address, &worker, prefix, now)
        .await
        .map_err(map_prefix_conflict)?;
    Ok(Json(SetResponse {
        address: saved.address.as_str().to_string(),
        worker: saved.worker,
        extranonce: format!("{:08x}", saved.prefix),
        updated_at: saved.updated_at,
    }))
}

// ─── helpers ─────────────────────────────────────────────────────

fn challenge_message(address: &str, nonce: &str, now: i64, expires_at: i64) -> String {
    // Address + nonce + expiry: proves control of THIS address, one-time (the
    // challenge is consumed and expires), so the signature never becomes a
    // reusable credential — that's the token's job.
    format!(
        "Blitzpool extranonce token request\n\
         Address: {address}\n\
         Nonce: {nonce}\n\
         Issued(ms): {now}\n\
         Expires(ms): {expires_at}"
    )
}

/// A random 32-byte token, hex-encoded (64 chars). The plaintext is returned to
/// the customer once; only its hash is stored.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG");
    hex::encode(bytes)
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Check the presented token against the stored hash for this address.
async fn verify_token(pool: &PgPool, address: &AddressId, presented: &str) -> Result<(), ApiError> {
    let presented = presented.trim();
    if presented.is_empty() {
        return Err(en_error("missing-token", StatusCode::UNAUTHORIZED));
    }
    let stored = bp_db::find_extranonce_token(pool, address)
        .await?
        .ok_or_else(|| en_error("no-token", StatusCode::UNAUTHORIZED))?;
    if sha256_hex(presented) != stored.token_hash {
        return Err(en_error("invalid-token", StatusCode::UNAUTHORIZED));
    }
    Ok(())
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

/// Reject an address that can't mine Solo, so it can't set an override the core
/// would silently never apply (the core gate is `state.stream == Solo`).
///
/// Two signals, both false-positive-free (a pure Solo address is in neither):
///  - **Group / Group-Solo / Blockparty membership** — persistent DB rows, and
///    membership overrides the port (`resolve_mode`), so it's always non-Solo.
///  - **Active PPLNS window presence** — an address contributing to the PPLNS
///    share window right now is mining PPLNS by port, which group membership
///    can't see. Gated strictly on live window shares; a past PPLNS miner with
///    only a balance row is not treated as active (it may have switched).
///
/// Residual: an *offline* PPLNS miner (aged out of the window, or not yet
/// connected) still slips through — the core Solo gate drops that safely and
/// logs it (see `maybe_apply_custom_extranonce`).
async fn ensure_solo_eligible(
    pool: &PgPool,
    pplns: Option<&bp_pplns_engine::engine::PplnsEngine>,
    address: &AddressId,
) -> Result<(), ApiError> {
    let in_group = bp_db::find_group_member_by_address(pool, address)
        .await?
        .is_some();
    let in_blockparty = bp_db::find_blockparty_member_by_address(pool, address)
        .await?
        .is_some();
    if in_group || in_blockparty {
        return Err(en_error("not-solo-mode", StatusCode::CONFLICT));
    }
    // Best-effort PPLNS-window check. On a window-read error we log and allow
    // rather than couple the feature to Redis availability — the core Solo gate
    // is the actual guarantee, this is just an earlier, clearer rejection.
    if let Some(engine) = pplns {
        match engine.reader().address_status(address.as_str()).await {
            Ok(status) if pplns_active(status.as_ref()) => {
                return Err(en_error("not-solo-mode", StatusCode::CONFLICT));
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                %e,
                "custom-en: PPLNS window check failed; allowing (core Solo gate still enforces it)"
            ),
        }
    }
    Ok(())
}

/// Whether a PPLNS address status means the address is *actively* mining PPLNS
/// (contributing to the current window), and thus not Solo-eligible. Absent
/// status or zero live shares → not active; a balance-only (past) miner is not
/// blocked, since it may have switched to Solo.
fn pplns_active(status: Option<&bp_pplns_engine::reader::AddressStatus>) -> bool {
    status
        .map(|s| s.current_window_shares > 0.0)
        .unwrap_or(false)
}

/// The `UNIQUE (address, prefix)` violation is a user error, not a 500: this
/// address already points another worker at that prefix, which in Solo would
/// have both workers grinding one search space (same payouts -> same coinbase).
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

    fn sign_recoverable(sk: &SecretKey, message: &str) -> String {
        let secp = Secp256k1::new();
        let hash = signed_msg_hash(message);
        let msg = Message::from_digest(hash.to_byte_array());
        let rec = secp.sign_ecdsa_recoverable(&msg, sk);
        MessageSignature::new(rec, true).to_base64()
    }

    /// The PPLNS-window branch of the Solo guard: block only on LIVE window
    /// shares, so a Solo address (never in the window) and a past PPLNS miner
    /// (balance but zero current shares) both pass.
    #[test]
    fn pplns_active_gates_on_live_window_shares() {
        use bp_pplns_engine::reader::AddressStatus;
        let with_shares = |shares: f64, balance: i64| AddressStatus {
            address: "bc1qexample".to_string(),
            balance_sats: balance,
            total_paid_sats: 0,
            current_window_shares: shares,
            current_window_percent: 0.0,
        };
        assert!(!pplns_active(None));
        assert!(pplns_active(Some(&with_shares(0.5, 0))));
        assert!(!pplns_active(Some(&with_shares(0.0, 12_345))));
    }

    #[test]
    fn parse_prefix_accepts_the_unowned_range() {
        assert_eq!(parse_prefix("02000000").unwrap(), 0x0200_0000);
        assert_eq!(parse_prefix("c0debabe").unwrap(), 0xc0de_babe);
        assert_eq!(parse_prefix("ffffffff").unwrap(), 0xffff_ffff);
        assert_eq!(parse_prefix("0xC0DEBABE").unwrap(), 0xc0de_babe);
        assert_eq!(parse_prefix("  c0debabe  ").unwrap(), 0xc0de_babe);
    }

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

    #[test]
    fn normalize_worker_mirrors_the_core() {
        assert_eq!(normalize_worker(""), "default");
        assert_eq!(normalize_worker("Rig1"), "Rig1");
        assert_eq!(normalize_worker("rig.1"), "rig.1");
        assert_eq!(normalize_worker(" spaced "), " spaced ");
    }

    /// The signed challenge is address-bound and verifies with a genuine
    /// signature — guards the message format against drifting out of sync with
    /// what actually gets signed (which would make every token issue fail).
    #[test]
    fn signed_challenge_message_verifies() {
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let cpk = CompressedPublicKey(sk.public_key(&Secp256k1::new()));
        let addr = Address::p2wpkh(&cpk, Network::Bitcoin).to_string();

        let msg = challenge_message(&addr, "nonce123", 1000, 2000);
        let sig = sign_recoverable(&sk, &msg);
        assert!(verify_message_signature(&addr, &msg, &sig, Network::Bitcoin).is_some());
        // A signature over a different message must not verify.
        let other = challenge_message(&addr, "different-nonce", 1000, 2000);
        let other_sig = sign_recoverable(&sk, &other);
        assert!(verify_message_signature(&addr, &msg, &other_sig, Network::Bitcoin).is_none());
    }

    /// Token hashing: the stored hash matches the SHA-256 of the plaintext, a
    /// wrong token doesn't, and a fresh token is 64 hex chars.
    #[test]
    fn token_hashing_round_trips() {
        let token = random_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        let hash = sha256_hex(&token);
        assert_eq!(hash.len(), 64);
        // Same token → same hash; a different token → different hash.
        assert_eq!(sha256_hex(&token), hash);
        assert_ne!(sha256_hex("not-the-token"), hash);
        // Known vector: SHA-256("") = e3b0c442...
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
