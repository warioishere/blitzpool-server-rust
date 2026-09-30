// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-cutting axum middleware for `bp-api`.
//!
//! `x-admin-token` validation is a single [`admin_auth::require_admin`]
//! tower middleware that injects an [`admin_auth::AdminAuth`] request
//! extension on success. Handlers mounted behind it can rely on the token
//! having been validated and do not read the header themselves.

pub mod admin_auth;
pub mod rate_limit;

pub use admin_auth::{require_admin, AdminAuth};
