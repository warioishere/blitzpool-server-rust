// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-cutting axum middleware for `bp-api`. Handlers behind
//! [`admin_auth::require_admin`] or [`address_auth::require_address`] rely on
//! the token being validated and do not read the header themselves.

pub mod address_auth;
pub mod admin_auth;
pub mod rate_limit;

pub use address_auth::{require_address, require_address_token, AddressAuth, AddressTokenSecret};
pub use admin_auth::{require_admin, AdminAuth};
