// SPDX-License-Identifier: AGPL-3.0-or-later

//! Invitation service — open-invite links.
//!
//! **Open** — admin generates a TTL-limited shareable link; multi-use;
//! anyone whose joining address is verified (email OR signature) can claim
//! it until TTL or manual revoke.
//!
//! Authentication: open-accept requires the link token AND a verified
//! address (email or signature). Admin paths (create, list, revoke)
//! require the group admin-token verified by [`GroupService`].

use std::sync::Arc;

use bp_db::PplnsGroupMemberRow;
use bp_group_mgmt::{invitation::InvitationKind, token::InvitationToken};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::InvitationServiceError;
use crate::hooks::GroupServiceHooks;
use crate::service::GroupService;
use crate::util::{normalize_address, now_ms};

/// Allowed TTL presets for open-invite links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenInviteTtl {
    OneHour,
    TwentyFourHours,
    SevenDays,
    ThirtyDays,
}

impl OpenInviteTtl {
    /// Map the preset to its millisecond delta from now.
    pub fn as_ms(self) -> i64 {
        const HOUR: i64 = 60 * 60 * 1000;
        const DAY: i64 = 24 * HOUR;
        match self {
            Self::OneHour => HOUR,
            Self::TwentyFourHours => 24 * HOUR,
            Self::SevenDays => 7 * DAY,
            Self::ThirtyDays => 30 * DAY,
        }
    }

    /// Parse from the wire-form (`"1h"` / `"24h"` / `"7d"` / `"30d"`).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "1h" => Self::OneHour,
            "24h" => Self::TwentyFourHours,
            "7d" => Self::SevenDays,
            "30d" => Self::ThirtyDays,
            _ => return None,
        })
    }
}

/// Public landing-page view for an open invite. Returned by
/// [`InvitationService::get_open_invite_public`]; safe to expose
/// without authentication (token IS the secret).
#[derive(Debug, Clone)]
pub struct OpenInvitePublicView {
    pub token: String,
    pub group_id: Uuid,
    pub group_name: String,
    pub expires_at: i64,
    pub approval_required: bool,
}

/// Returned by [`InvitationService::create_open_invite`].
#[derive(Debug, Clone)]
pub struct OpenInviteCreated {
    pub token: String,
    pub expires_at: i64,
    pub approval_required: bool,
}

/// Active open invite for a group — admin view, includes the token.
#[derive(Debug, Clone)]
pub struct OpenInviteActive {
    pub token: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub approval_required: bool,
}

/// Top-level invitation service (open-invite links only).
#[derive(Clone)]
pub struct InvitationService<H: GroupServiceHooks> {
    pool: PgPool,
    group_service: Arc<GroupService<H>>,
}

impl<H: GroupServiceHooks> InvitationService<H> {
    pub fn new(pool: PgPool, group_service: Arc<GroupService<H>>) -> Self {
        Self {
            pool,
            group_service,
        }
    }

    // ── Open invites ────────────────────────────────────────────

    /// Admin creates a fresh open-invite link, atomically revoking any
    /// previously-active one for the same group.
    pub async fn create_open_invite(
        &self,
        group_id: Uuid,
        ttl: OpenInviteTtl,
        admin_token: Option<&str>,
        approval_required: bool,
    ) -> Result<OpenInviteCreated, InvitationServiceError> {
        self.group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let now = now_ms();
        let expires_at = now + ttl.as_ms();
        let token = InvitationToken::generate()?;

        let mut tx = self.pool.begin().await.map_err(bp_db::DbError::from)?;
        bp_db::revoke_pending_open_invites_for_group(&mut *tx, group_id, now).await?;
        let row = bp_db::insert_pplns_group_invitation(
            &mut *tx,
            token.as_str(),
            group_id,
            None,
            None,
            InvitationKind::Open.as_str(),
            approval_required,
            now,
            expires_at,
        )
        .await?;
        tx.commit().await.map_err(bp_db::DbError::from)?;

        Ok(OpenInviteCreated {
            token: row.token,
            expires_at,
            approval_required,
        })
    }

    /// Admin view — currently-active (pending, not past-TTL) open
    /// invite for `group_id`, or `None`.
    pub async fn get_active_open_invite(
        &self,
        group_id: Uuid,
        admin_token: Option<&str>,
    ) -> Result<Option<OpenInviteActive>, InvitationServiceError> {
        self.group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let row =
            bp_db::find_pplns_group_active_open_invite_for_group(&self.pool, group_id).await?;
        let now = now_ms();
        Ok(row
            .filter(|r| r.expires_at >= now)
            .map(|r| OpenInviteActive {
                token: r.token,
                expires_at: r.expires_at,
                created_at: r.created_at,
                approval_required: r.approval_required,
            }))
    }

    /// Admin revokes the active open invite. Idempotent — no-op when
    /// no active link exists.
    pub async fn revoke_open_invite(
        &self,
        group_id: Uuid,
        admin_token: Option<&str>,
    ) -> Result<(), InvitationServiceError> {
        self.group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let now = now_ms();
        bp_db::revoke_pending_open_invites_for_group(&self.pool, group_id, now).await?;
        Ok(())
    }

    /// Public landing-page lookup. Returns `None` for unknown /
    /// wrong-type / past-TTL / dissolved-group tokens — every reason
    /// the link could be invalid collapses to one response shape so
    /// the page can't probe for "exists but inactive" rows.
    pub async fn get_open_invite_public(
        &self,
        token: &str,
    ) -> Result<Option<OpenInvitePublicView>, InvitationServiceError> {
        let invitation = bp_db::find_group_invitation(&self.pool, token).await?;
        let Some(invitation) = invitation else {
            return Ok(None);
        };
        if invitation.invite_type != InvitationKind::Open.as_str() || invitation.status != "pending"
        {
            return Ok(None);
        }
        let now = now_ms();
        if invitation.expires_at < now {
            return Ok(None);
        }
        let group = bp_db::find_group(&self.pool, invitation.group_id).await?;
        let group = match group {
            Some(g) if g.dissolved_at.is_none() => g,
            _ => return Ok(None),
        };
        Ok(Some(OpenInvitePublicView {
            token: invitation.token,
            group_id: invitation.group_id,
            group_name: group.name,
            expires_at: invitation.expires_at,
            approval_required: invitation.approval_required,
        }))
    }

    /// Public claim of an open invite by an address. Multi-use: the
    /// invitation row stays `pending` so others can also claim. The
    /// trust anchor is the verified-email binding on the claiming
    /// address.
    pub async fn accept_open_invite(
        &self,
        token: &str,
        address: &str,
    ) -> Result<PplnsGroupMemberRow, InvitationServiceError> {
        let invitation = bp_db::find_group_invitation(&self.pool, token).await?;
        let mut invitation = invitation.ok_or(InvitationServiceError::NotFound)?;
        if invitation.invite_type != InvitationKind::Open.as_str() {
            return Err(InvitationServiceError::NotFound);
        }
        if invitation.status != "pending" {
            // `revoked` or `expired` both surface as `expired`.
            return Err(InvitationServiceError::Expired);
        }
        let now = now_ms();
        if invitation.expires_at < now {
            bp_db::update_pplns_group_invitation_status_by_token(
                &self.pool,
                &invitation.token,
                "expired",
                None,
            )
            .await?;
            invitation.status = "expired".into();
            return Err(InvitationServiceError::Expired);
        }
        if invitation.approval_required {
            return Err(InvitationServiceError::ApprovalRequired);
        }
        let normalized =
            normalize_address(address).map_err(|_| InvitationServiceError::InvalidAddress)?;
        // Unified onboarding gate: the joining address must be verified by a
        // confirmed email OR a signature ownership proof.
        if !bp_db::is_address_verified(&self.pool, &normalized).await? {
            return Err(InvitationServiceError::EmailNotVerified);
        }

        let group = bp_db::find_group(&self.pool, invitation.group_id).await?;
        let _group = match group {
            Some(g) if g.dissolved_at.is_none() => g,
            _ => return Err(InvitationServiceError::GroupDissolved),
        };

        let existing = bp_db::find_group_member_by_address(&self.pool, &normalized).await?;
        if let Some(m) = existing {
            if m.group_id == invitation.group_id {
                return Err(InvitationServiceError::AlreadyMember);
            } else {
                return Err(InvitationServiceError::AddressInGroup);
            }
        }
        let member = self
            .group_service
            .add_member_without_admin(invitation.group_id, normalized.as_str())
            .await?;
        Ok(member)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_invite_ttl_parse_and_ms() {
        assert_eq!(OpenInviteTtl::parse("1h"), Some(OpenInviteTtl::OneHour));
        assert_eq!(
            OpenInviteTtl::parse("24h"),
            Some(OpenInviteTtl::TwentyFourHours)
        );
        assert_eq!(OpenInviteTtl::parse("7d"), Some(OpenInviteTtl::SevenDays));
        assert_eq!(OpenInviteTtl::parse("30d"), Some(OpenInviteTtl::ThirtyDays));
        assert!(OpenInviteTtl::parse("forever").is_none());
        assert_eq!(OpenInviteTtl::SevenDays.as_ms(), 7 * 24 * 60 * 60 * 1000);
    }
}
