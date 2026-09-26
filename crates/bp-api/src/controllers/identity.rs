// SPDX-License-Identifier: AGPL-3.0-or-later

//! `POST /api/identity/resolve` — turn a bare xpub into the ledger key the
//! rest of the API is addressed by.
//!
//! A rotating miner mines to an xpub, but every read endpoint is keyed by the
//! height-invariant `payout_id` (`"xpb" + base58(sha256(canonical
//! descriptor))`). The UI needs that key to build a dashboard URL, and it must
//! not compute it itself: the canonical descriptor is whatever
//! `bp-payout-descriptor` renders, checksum included, and a second
//! implementation of that in TypeScript would be a second place for the
//! mapping to drift. So the UI asks.
//!
//! The xpub travels in the **body**, never in the path: a path segment ends up
//! in access logs, and an xpub is the watch-only capability for the whole
//! payout branch.
//!
//! The mapping is a pure function of the key and the operator's flag. The one
//! write: a resolved identity is recorded in `miner_identity`, the same row
//! stratum intake writes when a miner connects with the xpub. That is what lets
//! a miner connect with the **id** instead, which rented hashrate does: MRR,
//! Braiins and the marketplace are configured from the dashboard key, and the
//! pool admits a known id by rehydrating this row. A pure renter who never
//! mined with the xpub would otherwise have no row. Rate-limited because it
//! parses attacker-chosen input and writes.

use axum::{extract::State, response::Json, routing::post, Router};
use bp_group_mgmt_engine::{EmailHooks, GroupServiceHooks};
use bp_payout_descriptor::{intake_wire_identity, IntakeError};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::rate_limit;
use crate::state::SharedState;

pub(crate) fn routes<H, M>() -> Router<SharedState<H, M>>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    Router::new().route(
        "/api/identity/resolve",
        post(resolve::<H, M>).layer(rate_limit::per_minute_layer(20)),
    )
}

#[derive(Deserialize)]
struct ResolveRequest {
    xpub: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ResolvedIdentity {
    /// The ledger key: what goes into `/api/client/:address` and the
    /// dashboard URL.
    payout_id: String,
    /// The pool's descriptor for this key, for the miner to check against
    /// `bitcoin-cli deriveaddresses "<desc>" [H,H]`.
    descriptor: String,
}

async fn resolve<H, M>(
    State(state): State<SharedState<H, M>>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ResolvedIdentity>, ApiError>
where
    H: GroupServiceHooks + 'static,
    M: EmailHooks + 'static,
{
    let resolved = resolve_identity(&req.xpub, state.allow_rotating_identities)?;
    // Idempotent, content-addressed: the key is the hash of the descriptor, so
    // this can only ever write the row intake would write for the same xpub.
    // A failed write fails the call. Answering without it would send a miner
    // into rentals that the pool then refuses to credit.
    let now_ms = chrono::Utc::now().timestamp_millis();
    bp_db::upsert_rotating_identity(
        &state.pool,
        &resolved.payout_id,
        &resolved.descriptor,
        now_ms,
    )
    .await?;
    Ok(Json(resolved))
}

/// The whole endpoint, minus axum. Goes through the SAME intake function
/// stratum uses, so the API can never resolve a key the pool would refuse to
/// mine for, or refuse one it would accept.
fn resolve_identity(raw: &str, allow_rotating: bool) -> Result<ResolvedIdentity, ApiError> {
    match intake_wire_identity(raw, allow_rotating) {
        Ok(Some(payout)) => Ok(ResolvedIdentity {
            payout_id: payout.payout_id().as_str().to_string(),
            descriptor: payout.canonical_descriptor().to_string(),
        }),
        // Not an extended-key attempt at all (an address, junk): this
        // endpoint has nothing to resolve.
        Ok(None) => Err(ApiError::InvalidXpub),
        Err(IntakeError::FeatureDisabled) => Err(ApiError::RotatingIdentitiesDisabled),
        Err(_) => Err(ApiError::InvalidXpub),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_payout_descriptor::RotatingPayout;

    /// BIP-32 test vector 1, master public key (published, no funds).
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    #[test]
    fn an_xpub_resolves_to_the_same_key_stratum_intake_gives_it() {
        let got = resolve_identity(XPUB, true).expect("resolves");
        let want = RotatingPayout::from_xpub_str(XPUB).expect("intake");
        assert_eq!(got.payout_id, want.payout_id().as_str());
        assert!(got.payout_id.starts_with("xpb"));
        assert_eq!(got.descriptor, want.canonical_descriptor());
    }

    #[test]
    fn the_operator_flag_gates_it_and_says_so() {
        let err = resolve_identity(XPUB, false).unwrap_err();
        assert_eq!(err.code(), "rotating-identities-disabled");
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn an_address_or_junk_is_not_an_xpub_whatever_the_flag_says() {
        // None of these is an extended-key ATTEMPT (`looks_like_extended_key`
        // wants the prefix AND the length), so the flag is never consulted.
        for raw in [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "",
            "xpubnotakey",
        ] {
            for allow in [true, false] {
                let err = resolve_identity(raw, allow).unwrap_err();
                assert_eq!(err.code(), "invalid-xpub", "raw={raw:?} allow={allow}");
            }
        }
    }

    #[test]
    fn a_key_shaped_string_that_is_not_a_key_reports_like_stratum_intake() {
        // Right prefix, right length, wrong checksum: an attempt. With the
        // flag off it hears about the flag (what stratum intake tells the
        // same miner); with it on, that the key is no good.
        let mangled = format!("{}xx", &XPUB[..XPUB.len() - 2]);
        assert_eq!(
            resolve_identity(&mangled, false).unwrap_err().code(),
            "rotating-identities-disabled"
        );
        assert_eq!(
            resolve_identity(&mangled, true).unwrap_err().code(),
            "invalid-xpub"
        );
    }

    #[test]
    fn a_private_key_is_refused_and_not_echoed() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let err = resolve_identity(xprv, true).unwrap_err();
        assert_eq!(err.code(), "invalid-xpub");
        assert!(!err.to_string().contains("xprv"));
    }
}
