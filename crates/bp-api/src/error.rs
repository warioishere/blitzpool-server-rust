// SPDX-License-Identifier: AGPL-3.0-or-later

//! Uniform JSON error body for every endpoint.
//!
//! Response shape: `{"code": "string", "message": "human"}` plus an HTTP
//! status code. The UI maps `code` to localised text, so the error code
//! strings are kept stable for UI localisation.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Uniform error type — every controller returns `Result<T, ApiError>`.
/// The IntoResponse impl assembles the JSON envelope and the matching
/// status code.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid query param: {0}")]
    InvalidQuery(&'static str),
    #[error("group-service: {code}")]
    GroupService {
        code: &'static str,
        status: StatusCode,
    },
    #[error("invitation-service: {code}")]
    Invitation {
        code: &'static str,
        status: StatusCode,
    },
    #[error("join-request-service: {code}")]
    JoinRequest {
        code: &'static str,
        status: StatusCode,
    },
    #[error("blockparty-service: {code}")]
    Blockparty {
        code: &'static str,
        status: StatusCode,
    },
    #[error("database error: {0}")]
    Db(#[from] bp_db::DbError),
    #[error("engine error: {0}")]
    PplnsEngine(#[from] bp_pplns_engine::engine::EngineError),
    #[error("group-solo engine: {0}")]
    GroupSoloEngine(#[from] bp_group_solo_engine::engine::EngineError),
    #[error("rpc: {0}")]
    Rpc(#[from] bp_bitcoin::RpcError),
    #[error("upstream service unavailable: {0}")]
    Unavailable(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    /// Stable wire-code returned in the JSON envelope.
    pub fn code(&self) -> &str {
        match self {
            Self::NotFound => "not-found",
            Self::BadRequest(_) => "bad-request",
            Self::InvalidAddress => "invalid-address",
            Self::InvalidQuery(_) => "invalid-query",
            Self::GroupService { code, .. }
            | Self::Invitation { code, .. }
            | Self::JoinRequest { code, .. }
            | Self::Blockparty { code, .. } => code,
            Self::Db(_) | Self::PplnsEngine(_) | Self::GroupSoloEngine(_) | Self::Internal(_) => {
                "internal-error"
            }
            Self::Rpc(_) | Self::Unavailable(_) => "upstream-unavailable",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) | Self::InvalidAddress | Self::InvalidQuery(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::GroupService { status, .. }
            | Self::Invitation { status, .. }
            | Self::JoinRequest { status, .. }
            | Self::Blockparty { status, .. } => *status,
            Self::Db(_) | Self::PplnsEngine(_) | Self::GroupSoloEngine(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Rpc(_) | Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            code: self.code(),
            message: self.to_string(),
        };
        if status.is_server_error() {
            tracing::warn!(target: "bp_api", code = %body.code, error = %self,
                "endpoint returned server error");
        }
        (status, Json(body)).into_response()
    }
}

/// Map `bp_group_mgmt_engine::GroupServiceError` to an `ApiError`. The
/// service errors carry their own code; we additionally pick the right
/// HTTP status so the UI sees 403/404/409 instead of always 500.
impl From<bp_group_mgmt_engine::GroupServiceError> for ApiError {
    fn from(e: bp_group_mgmt_engine::GroupServiceError) -> Self {
        use bp_group_mgmt_engine::GroupServiceError as G;
        // Leak the &str — the wire-codes are static; this is a one-time
        // conversion per request.
        let code: &'static str = match e.code() {
            "missing-token" => "missing-token",
            "not-found" => "not-found",
            "invalid-token" => "invalid-token",
            "invalid-name" => "invalid-name",
            "invalid-address" => "invalid-address",
            "name-taken" => "name-taken",
            "address-in-group" => "address-in-group",
            "address-in-blockparty" => "address-in-blockparty",
            "already-member" => "already-member",
            "not-member" => "not-member",
            "creator-cannot-be-removed" => "creator-cannot-be-removed",
            "already-creator" => "already-creator",
            "member-still-active" => "member-still-active",
            "invalid-interval" => "invalid-interval",
            "invalid-preset" => "invalid-preset",
            "invalid-timezone" => "invalid-timezone",
            "invalid-bonus" => "invalid-bonus",
            "invalid-max-members" => "invalid-max-members",
            "group-full" => "group-full",
            "incomplete-schedule" => "incomplete-schedule",
            _ => "internal-error",
        };
        let status = match e {
            G::MissingToken | G::InvalidToken => StatusCode::UNAUTHORIZED,
            G::NotFound | G::NotMember => StatusCode::NOT_FOUND,
            G::CreatorCannotBeRemoved
            | G::MemberStillActive { .. }
            | G::NameTaken
            | G::AddressInGroup
            | G::AddressInBlockparty
            | G::AlreadyMember
            | G::GroupFull
            | G::AlreadyCreator => StatusCode::CONFLICT,
            G::InvalidName
            | G::InvalidAddress
            | G::InvalidInterval
            | G::InvalidPreset
            | G::InvalidTimezone
            | G::InvalidBonus
            | G::InvalidMaxMembers
            | G::IncompleteSchedule => StatusCode::BAD_REQUEST,
            G::Db(_) | G::Token(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::GroupService { code, status }
    }
}

/// Map `bp_blockparty_engine::BlockpartyServiceError` to an `ApiError`.
/// Wire codes pass through verbatim; the HTTP status comes from the
/// variant discriminant so 401/403/404/409/424/500 land correctly.
impl From<bp_blockparty_engine::BlockpartyServiceError> for ApiError {
    fn from(e: bp_blockparty_engine::BlockpartyServiceError) -> Self {
        use bp_blockparty_engine::BlockpartyServiceError as B;
        let code: &'static str = match e.code() {
            "missing-token" => "missing-token",
            "invalid-token" => "invalid-token",
            "missing-member-token" => "missing-member-token",
            "invalid-member-token" => "invalid-member-token",
            "member-not-confirmed" => "member-not-confirmed",
            "not-found" => "not-found",
            "not-member" => "not-member",
            "invalid-name" => "invalid-name",
            "invalid-address" => "invalid-address",
            "invalid-email" => "invalid-email",
            "invalid-percent" => "invalid-percent",
            "invalid-splits-sum" => "invalid-splits-sum",
            "invalid-state" => "invalid-state",
            "name-taken" => "name-taken",
            "admin-address-taken" => "admin-address-taken",
            "address-in-blockparty" => "address-in-blockparty",
            "address-in-pplns-group" => "address-in-pplns-group",
            "email-not-verified" => "email-not-verified",
            "admin-cannot-rejoin" => "admin-cannot-rejoin",
            "admin-cannot-be-removed" => "admin-cannot-be-removed",
            "not-editable" => "not-editable",
            "no-members" => "no-members",
            "dissolve-cooldown" => "dissolve-cooldown",
            _ => "internal-error",
        };
        let status = match e {
            B::MissingToken | B::InvalidToken | B::MissingMemberToken | B::InvalidMemberToken => {
                StatusCode::UNAUTHORIZED
            }
            B::MemberNotConfirmed | B::DissolveCooldown => StatusCode::FORBIDDEN,
            B::NotFound | B::NotMember => StatusCode::NOT_FOUND,
            B::NameTaken
            | B::AdminAddressTaken
            | B::AddressInBlockparty
            | B::AddressInPplnsGroup
            | B::AdminCannotRejoin
            | B::AdminCannotBeRemoved
            | B::NotEditable
            | B::InvalidState => StatusCode::CONFLICT,
            B::EmailNotVerified => StatusCode::FAILED_DEPENDENCY,
            B::InvalidName
            | B::InvalidAddress
            | B::InvalidEmail
            | B::InvalidPercent
            | B::InvalidSplitsSum
            | B::NoMembers => StatusCode::BAD_REQUEST,
            B::Db(_) | B::Token(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::Blockparty { code, status }
    }
}
