// SPDX-License-Identifier: AGPL-3.0-or-later

//! The pool's `SetupConnection.Error` / `*.Error` codes against the ones the
//! SV2 message crates ship.
//!
//! ## Why this is a test and not a refactor
//!
//! `stratum_core` re-exports canonical `ERROR_CODE_*` constants from
//! `common_messages_sv2`, `job_declaration_sv2` and `mining_sv2`. Aliasing our
//! constants onto them would look tidier and would be the wrong trade: a
//! dependency bump could then change what the pool writes on the wire with
//! nothing in the diff to see. `stale-chain-tip` is the one declaration error
//! a reference JD-client retries instead of leaving the pool over, so that
//! string is not something a `cargo update` gets to decide.
//!
//! So the strings stay ours, and this asserts they still agree. A bump that
//! moves a code fails here, loudly, instead of shifting a wire meaning
//! quietly.
//!
//! ## Why the same string appears more than once
//!
//! Upstream's model is one constant per **(message, code)** pair, not per
//! string: `mining_sv2` ships `"invalid-channel-id"` three times, once each
//! for `UpdateChannel`, `SubmitShares` and `SetCustomMiningJob`. Ours follow
//! the same shape — `ERR_STALE_CHAIN_TIP` exists on the JDP side for
//! `DeclareMiningJob.Error` and on the mining side for
//! `SetCustomMiningJob.Error`, and those are two upstream constants that
//! happen to share a value. Collapsing them by string would merge message
//! contexts that upstream deliberately keeps apart.

use stratum_core::common_messages_sv2 as common;
use stratum_core::job_declaration_sv2 as jd;
use stratum_core::mining_sv2 as mining;

use bp_stratum_v2::jdp::client as jdp_client;
use bp_stratum_v2::mining::client as mining_client;
use bp_stratum_v2::mining::submit as mining_submit;

/// Every code we send that the SV2 message crates also name, paired with the
/// upstream constant for the SAME message. `(ours, upstream, label)`.
const PAIRS: &[(&str, &str, &str)] = &[
    // ── SetupConnection (common) ────────────────────────────────────
    (
        bp_stratum_v2::codec_common::ERR_PROTOCOL_VERSION_MISMATCH,
        common::ERROR_CODE_SETUP_CONNECTION_PROTOCOL_VERSION_MISMATCH,
        "SetupConnection.Error / protocol-version-mismatch (mining and JDP)",
    ),
    (
        jdp_client::ERR_UNSUPPORTED_PROTOCOL,
        common::ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL,
        "JDP SetupConnection.Error / unsupported-protocol",
    ),
    (
        mining_client::ERR_UNSUPPORTED_PROTOCOL,
        common::ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL,
        "Mining SetupConnection.Error / unsupported-protocol",
    ),
    // Cross-message ON PURPOSE, and the only row in this table that is.
    // The pool raises this on `DeclareMiningJob.Error`, but pairs it with a
    // `SetupConnection` constant, because `job_declaration_sv2` ships no code
    // for the condition: a `DeclareMiningJob` arriving on a session that never
    // negotiated the `DECLARE_TX_DATA` flag. Of the seven codes it does ship,
    // only `invalid-job` would fit at all, and it says strictly less to
    // whoever reads the log — SV2 JDP/DeclareMiningJob.Error asks for a
    // "human-readable error code", and names no list to choose from.
    //
    // Still pinned here rather than dropped: the pairing is what stops a
    // dependency bump from changing the STRING under us without anyone
    // looking. Compare `mining_client::ERR_INVALID_JOB_ID` further down, which
    // is absent because upstream ships nothing to pair it with at all.
    (
        jdp_client::ERR_UNSUPPORTED_FEATURE_FLAGS,
        common::ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
        "JDP DeclareMiningJob.Error / unsupported-feature-flags \
         (a SetupConnection code, borrowed — see the comment above)",
    ),
    // ── DeclareMiningJob (job declaration) ──────────────────────────
    (
        jdp_client::ERR_INVALID_MINING_JOB_TOKEN,
        jd::ERROR_CODE_DECLARE_MINING_JOB_INVALID_MINING_JOB_TOKEN,
        "JDP DeclareMiningJob.Error / invalid-mining-job-token",
    ),
    (
        jdp_client::ERR_STALE_CHAIN_TIP,
        jd::ERROR_CODE_DECLARE_MINING_JOB_STALE_CHAIN_TIP,
        "JDP DeclareMiningJob.Error / stale-chain-tip",
    ),
    (
        jdp_client::ERR_MISSING_TXS,
        jd::ERROR_CODE_DECLARE_MINING_JOB_MISSING_TXS,
        "JDP DeclareMiningJob.Error / missing-txs",
    ),
    // ── SetCustomMiningJob (mining) ─────────────────────────────────
    (
        mining_client::ERR_INVALID_MINING_JOB_TOKEN,
        mining::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MINING_JOB_TOKEN,
        "SetCustomMiningJob.Error / invalid-mining-job-token",
    ),
    (
        mining_client::ERR_STALE_CHAIN_TIP,
        mining::ERROR_CODE_SET_CUSTOM_MINING_JOB_STALE_CHAIN_TIP,
        "SetCustomMiningJob.Error / stale-chain-tip",
    ),
    (
        mining_client::ERR_INVALID_NBITS,
        mining::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_NBITS,
        "SetCustomMiningJob.Error / invalid-nbits",
    ),
    // `ERR_INVALID_CHANNEL_ID` on the mining side is raised for three
    // different messages (`SubmitShares.Error`, `UpdateChannel.Error`,
    // `SetCustomMiningJob.Error`). All three upstream constants are checked,
    // because a bump that moved only one of them would still be a divergence.
    (
        mining_client::ERR_INVALID_CHANNEL_ID,
        mining::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_CHANNEL_ID,
        "SetCustomMiningJob.Error / invalid-channel-id",
    ),
    (
        mining_client::ERR_INVALID_CHANNEL_ID,
        mining::ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID,
        "UpdateChannel.Error / invalid-channel-id",
    ),
    (
        mining_client::ERR_INVALID_CHANNEL_ID,
        mining::ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
        "SubmitShares.Error / invalid-channel-id (mining::client)",
    ),
    // ── OpenMiningChannel (mining) ──────────────────────────────────
    (
        mining_client::ERR_UNKNOWN_USER,
        mining::ERROR_CODE_OPEN_MINING_CHANNEL_UNKNOWN_USER,
        "OpenMiningChannel.Error / unknown-user",
    ),
    (
        mining_client::ERR_MAX_TARGET_OUT_OF_RANGE,
        mining::ERROR_CODE_OPEN_MINING_CHANNEL_MAX_TARGET_OUT_OF_RANGE,
        "OpenMiningChannel.Error / max-target-out-of-range",
    ),
    (
        mining_client::ERR_MIN_EXTRANONCE_SIZE_TOO_LARGE,
        mining::ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE,
        "OpenMiningChannel.Error / min-extranonce-size-too-large",
    ),
    // ── SubmitShares (mining) ───────────────────────────────────────
    (
        mining_submit::ERR_INVALID_CHANNEL_ID,
        mining::ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
        "SubmitShares.Error / invalid-channel-id",
    ),
    (
        mining_submit::ERR_INVALID_JOB_ID,
        mining::ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
        "SubmitShares.Error / invalid-job-id",
    ),
    (
        mining_submit::ERR_STALE_SHARE,
        mining::ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
        "SubmitShares.Error / stale-share",
    ),
    (
        mining_submit::ERR_DUPLICATE_SHARE,
        mining::ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE,
        "SubmitShares.Error / duplicate-share",
    ),
    (
        mining_submit::ERR_DIFFICULTY_TOO_LOW,
        mining::ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
        "SubmitShares.Error / difficulty-too-low",
    ),
    (
        mining_submit::ERR_BAD_EXTRANONCE_SIZE,
        mining::ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
        "SubmitShares.Error / bad-extranonce-size",
    ),
    // `mining_client::ERR_INVALID_JOB_ID` is deliberately absent: it is raised
    // on `SetCustomMiningJob.Error`, and upstream ships no
    // `ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_JOB_ID` to pair it with.
];

#[test]
fn every_shared_error_code_still_matches_the_sv2_message_crates() {
    for (ours, upstream, label) in PAIRS {
        assert_eq!(
            ours, upstream,
            "{label}: this pool sends {ours:?} but the SV2 message crate now says {upstream:?}. \
             Either the dependency bump changed a spec code — then change ours to match and \
             think about what it does to a connected client — or the pairing in this table is \
             wrong."
        );
    }
}

/// Where the pool knowingly says something else.
///
/// Pinned so the divergence is a decision on the record rather than an
/// accident, and so a later bump cannot quietly close the gap without anyone
/// looking at it. Changing any of these is a wire-behaviour change: an
/// SRI JD-client treats every `DeclareMiningJob.Error` except
/// `stale-chain-tip` as a reason to leave the pool.
#[test]
fn the_codes_we_diverge_on_are_still_the_ones_we_chose() {
    // A coinbase that violates its referenced payout set. Upstream names
    // `invalid-coinbase-tx` for both messages; the pool is more specific
    // about which job parameter was at fault.
    assert_eq!(
        jdp_client::ERR_INVALID_JOB_PARAM_COINBASE,
        "invalid-job-param-value-coinbase_tx_outputs"
    );
    assert_eq!(
        mining_client::ERR_INVALID_JOB_PARAM_COINBASE_OUTPUTS,
        "invalid-job-param-value-coinbase_tx_outputs"
    );
    assert_eq!(
        jd::ERROR_CODE_DECLARE_MINING_JOB_INVALID_COINBASE_TX,
        "invalid-coinbase-tx"
    );
    assert_eq!(
        mining::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_TX,
        "invalid-coinbase-tx"
    );
}

/// Codes the pool defines because SV2 has none for what they mean. Pinned so
/// a later upstream release that DOES name one is noticed here rather than
/// left to diverge.
#[test]
fn the_pool_only_invents_a_code_where_sv2_names_none() {
    for (ours, label) in [
        (mining_client::ERR_ADDRESS_LOCKED, "address-locked"),
        (
            mining_client::ERR_CUSTOM_JOB_REQUIRES_SOLO,
            "custom-jobs-require-solo",
        ),
        (
            mining_client::ERR_INVALID_JOB_PARAM_TOKEN_MISMATCH,
            "invalid-job-param-value-token-mismatch",
        ),
        (
            mining_client::ERR_INVALID_JOB_PARAM_DECLARATION_MISMATCH,
            "invalid-job-param-value-declaration-mismatch",
        ),
    ] {
        assert_eq!(ours, label, "pool-defined code changed");
    }
}
