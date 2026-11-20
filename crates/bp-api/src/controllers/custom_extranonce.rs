// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/api/address/extranonce/*`: a Solo address sets its own extranonce prefix
//! per worker. A signed challenge yields a long-lived bearer token; that is
//! acceptable because the feature cannot move money. Top bytes owned by the
//! SV1/SV2 allocators are refused, so a hand-set prefix is never handed out twice.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use bp_common::AddressId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashSet;

use super::address_ownership::{
    check_signed_challenge, issue_challenge, parse_supported_address, ChallengeBody,
    ChallengeResponse, SignedChallengeBody,
};
use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;
use bp_db::ChallengePurpose;

/// Highest top byte an allocator owns; a new allocator must widen it. The DB
/// check `pplns_custom_extranonce_prefix_unreserved` carries the same bound,
/// change both together.
const RESERVED_TOP_BYTE_MAX: u32 =
    if bp_common::extranonce::SV1_WORKER_ID > bp_common::extranonce::SV2_WORKER_ID {
        bp_common::extranonce::SV1_WORKER_ID
    } else {
        bp_common::extranonce::SV2_WORKER_ID
    };

pub(crate) fn routes() -> Router<SharedState> {
    Router::new()
        .route(
            // Rate-limited to match the ownership challenge: 5/min per client IP.
            "/api/address/extranonce/challenge",
            post(challenge).layer(rate_limit::per_minute_layer(5)),
        )
        .route(
            "/api/address/extranonce/token",
            post(token).layer(rate_limit::per_minute_layer(5)),
        )
        .route(
            "/api/address/extranonce/set",
            post(set).layer(rate_limit::per_minute_layer(30)),
        )
}

// ─── POST /api/address/extranonce/challenge ──────────────────────

async fn challenge(
    State(state): State<SharedState>,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let address = parse_supported_address(&body.address, state.network)?;
    // Up front, so no one signs for a token that could never set an override.
    ensure_solo_eligible(&state.pool, state.pplns.as_deref(), &address).await?;
    issue_challenge(&state, &address, ChallengePurpose::Extranonce).await
}

// ─── POST /api/address/extranonce/token ──────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    address: String,
    /// Only its hash is kept server-side, so it cannot be recovered later.
    token: String,
    created_at: i64,
}

async fn token(
    State(state): State<SharedState>,
    Json(body): Json<SignedChallengeBody>,
) -> Result<Json<TokenResponse>, ApiError> {
    let signed = check_signed_challenge(&state, ChallengePurpose::Extranonce, &body).await?;
    // Overwrites (revokes) any prior token.
    let token = random_token();
    let now = bp_common::now_ms();
    bp_db::upsert_extranonce_token(&state.pool, &signed.address, &sha256_hex(&token), now).await?;
    bp_db::delete_address_challenge(&state.pool, &signed.address, ChallengePurpose::Extranonce)
        .await?;
    Ok(Json(TokenResponse {
        address: signed.address.as_str().to_string(),
        token,
        created_at: now,
    }))
}

// ─── POST /api/address/extranonce/set ────────────────────────────

/// Bounded so one request cannot pin the API on an unbounded transaction.
const MAX_BATCH_WORKERS: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetEntry {
    worker: String,
    extranonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetBody {
    address: String,
    workers: Vec<SetEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetEntryResult {
    worker: String,
    /// Echoed as 8 hex chars, the same shape the request used.
    extranonce: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetResponse {
    address: String,
    updated: Vec<SetEntryResult>,
    updated_at: i64,
}

/// All-or-nothing, so a fleet is never left half-applied. The token travels in
/// the header to stay out of body logs. A swap between two of the address's
/// own workers is legal, see [`bp_db::upsert_custom_extranonces_batch`].
async fn set(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SetBody>,
) -> Result<Json<SetResponse>, ApiError> {
    let address = parse_supported_address(&body.address, state.network)?;

    if body.workers.is_empty() {
        return Err(en_error("empty-batch", StatusCode::BAD_REQUEST));
    }
    if body.workers.len() > MAX_BATCH_WORKERS {
        return Err(en_error("batch-too-large", StatusCode::BAD_REQUEST));
    }

    // Validated before the database, so the error can name the entry.
    let mut entries: Vec<(String, u32)> = Vec::with_capacity(body.workers.len());
    let mut seen_workers: HashSet<String> = HashSet::with_capacity(body.workers.len());
    let mut seen_prefixes: HashSet<u32> = HashSet::with_capacity(body.workers.len());
    for entry in &body.workers {
        // The name the core resolves for the same miner, so the override matches.
        let worker = bp_common::worker_name(Some(&entry.worker));
        let prefix = parse_prefix(&entry.extranonce)?;
        if !seen_prefixes.insert(prefix) {
            // Unlike a swap, one prefix twice in a request can never be satisfied.
            return Err(en_error(
                "duplicate-extranonce-in-batch",
                StatusCode::BAD_REQUEST,
            ));
        }
        if !seen_workers.insert(worker.clone()) {
            return Err(en_error(
                "duplicate-worker-in-batch",
                StatusCode::BAD_REQUEST,
            ));
        }
        entries.push((worker, prefix));
    }

    ensure_solo_eligible(&state.pool, state.pplns.as_deref(), &address).await?;
    verify_token(&state.pool, &address, &bearer_token(&headers)).await?;

    let now = bp_common::now_ms();
    let saved = bp_db::upsert_custom_extranonces_batch(&state.pool, &address, &entries, now)
        .await
        .map_err(map_prefix_conflict)?;
    // `/api/client/:address` serves the extranonce per worker.
    state
        .cache
        .invalidate(&super::client::client_info_cache_key(&address))
        .await;

    let updated_at = saved.first().map(|r| r.updated_at).unwrap_or(now);
    Ok(Json(SetResponse {
        address: address.as_str().to_string(),
        updated: saved
            .into_iter()
            .map(|r| SetEntryResult {
                worker: r.worker,
                extranonce: format!("{:08x}", r.prefix),
            })
            .collect(),
        updated_at,
    }))
}

// ─── helpers ─────────────────────────────────────────────────────

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS CSPRNG");
    hex::encode(bytes)
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Empty when absent or malformed, so [`verify_token`] reports both as
/// `missing-token`.
fn bearer_token(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim()
        .to_string()
}

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

/// Refuses an address that cannot mine Solo, whose override the core would never
/// apply: group or Blockparty members, and addresses with live PPLNS window
/// shares. An offline PPLNS miner slips through; the core Solo gate drops that.
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
    // A read error allows: the core Solo gate is the guarantee, this is only
    // an earlier, clearer rejection.
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

/// Live window shares only: a balance-only past miner may have switched to Solo.
fn pplns_active(status: Option<&bp_pplns_engine::reader::AddressStatus>) -> bool {
    status
        .map(|s| s.current_window_shares > 0.0)
        .unwrap_or(false)
}

/// `UNIQUE (address, prefix)` is a user error, not a 500: two Solo workers on
/// one prefix would grind the same search space.
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

    /// Only live window shares block; a balance-only past PPLNS miner passes.
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

    /// A token hashes stably, a wrong token does not match, tokens are 64 hex.
    #[test]
    fn token_hashing_round_trips() {
        let token = random_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        let hash = sha256_hex(&token);
        assert_eq!(hash.len(), 64);
        assert_eq!(sha256_hex(&token), hash);
        assert_ne!(sha256_hex("not-the-token"), hash);
        // Known vector: SHA-256("") = e3b0c442...
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
