// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-controller handler modules. Routing helpers in each module
//! return an axum `Router<SharedState<H, M>>` so [`crate::lib`] can
//! merge them into the public root router.

pub(crate) mod address_ownership;
pub(crate) mod blockparty;
pub(crate) mod client;
pub(crate) mod downstream_report;
pub(crate) mod email;
pub(crate) mod external_share;
pub(crate) mod groups;
pub(crate) mod info;
pub(crate) mod invitation;
pub(crate) mod pplns;
pub(crate) mod push;
