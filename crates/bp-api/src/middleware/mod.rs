// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-cutting axum middleware for `bp-api`. Handlers behind
//! [`admin_auth::require_admin`] rely on the token being validated and do not
//! read the header themselves.

pub mod admin_auth;
pub mod rate_limit;

pub use admin_auth::{require_admin, AdminAuth};
