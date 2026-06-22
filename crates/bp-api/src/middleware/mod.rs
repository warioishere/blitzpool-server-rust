// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-cutting axum middleware for `bp-api`.
//!
//! The per-handler `x-admin-token` validation is lifted from inline
//! call-sites in `controllers/groups.rs` into a single
//! [`admin_auth::require_admin`] tower middleware that injects an
//! [`admin_auth::AdminAuth`] request extension on success. Handlers
//! that are mounted behind the middleware can rely on the token
//! having been validated upstream and no longer pluck the header
//! themselves.

pub mod admin_auth;
pub mod rate_limit;

pub use admin_auth::{require_admin, AdminAuth};
