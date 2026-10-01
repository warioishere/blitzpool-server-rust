// SPDX-License-Identifier: AGPL-3.0-or-later

//! Invitation kind stored in `pplns_group_invitation."inviteType"`.

/// The only invitation kind: a TTL-limited shareable link, claimable by
/// whoever holds it until it expires or is revoked.
pub const OPEN_INVITE_TYPE: &str = "open";
