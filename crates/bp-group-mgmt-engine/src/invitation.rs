// SPDX-License-Identifier: AGPL-3.0-or-later

//! Invitation service — two flavours share one table:
//!
//! - **Directed** — admin pre-binds an address + email; one-shot;
//!   emailed; auto-expires after 7 days.
//! - **Open** — admin generates a TTL-limited shareable link; multi-use;
//!   anyone with a verified-email binding for their address can claim
//!   it until TTL or manual revoke.
//!
//! Authentication: directed-accept requires the secret token (delivered
//! by email); open-accept requires the link token AND a verified email
//! binding on the joining address. Admin paths (create, cancel, list,
//! revoke) require the group admin-token verified by [`GroupService`].

use std::sync::Arc;

use bp_common::AddressId;
use bp_db::{PplnsGroupInvitationRow, PplnsGroupMemberRow, PplnsGroupRow};
use bp_group_mgmt::{
    invitation::{invitation_ttl_ms, InvitationKind},
    token::InvitationToken,
};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::email_hooks::{EmailHooks, InvitationEmailContext};
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

/// Configuration shared across the invitation paths. Currently just
/// the base URL used to assemble accept-links into emails. Populated
/// by `bin/blitzpool` from env at startup.
#[derive(Debug, Clone)]
pub struct InvitationServiceConfig {
    /// Pool base URL without trailing slash — combined with
    /// `/#/invite/<token>` to form the per-invite landing page.
    /// `None` causes [`InvitationServiceError::ConfigMissing`] on any
    /// path that needs to email the link.
    pub pool_base_url: Option<String>,
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

/// Public view of a directed pending invitation for a specific
/// address. Drives the "you have pending invitations" banner —
/// deliberately omits the token (the address holder accepts via the
/// link delivered by email).
#[derive(Debug, Clone)]
pub struct PendingForAddressView {
    pub group_id: Uuid,
    pub group_name: String,
    pub inviter_address: AddressId,
    pub masked_email: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Returned by [`InvitationService::create_open_invite`].
#[derive(Debug, Clone)]
pub struct OpenInviteCreated {
    pub token: String,
    pub expires_at: i64,
    pub approval_required: bool,
}

/// Returned by [`InvitationService::create_invitation`].
#[derive(Debug, Clone)]
pub struct DirectedInvitationCreated {
    pub token: String,
    pub email: String,
    pub expires_at: i64,
}

/// Active open invite for a group — admin view, includes the token.
#[derive(Debug, Clone)]
pub struct OpenInviteActive {
    pub token: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub approval_required: bool,
}

/// Top-level invitation service.
#[derive(Clone)]
pub struct InvitationService<H: GroupServiceHooks, M: EmailHooks> {
    pool: PgPool,
    group_service: Arc<GroupService<H>>,
    email: Arc<M>,
    config: InvitationServiceConfig,
}

impl<H: GroupServiceHooks, M: EmailHooks> InvitationService<H, M> {
    pub fn new(
        pool: PgPool,
        group_service: Arc<GroupService<H>>,
        email: Arc<M>,
        config: InvitationServiceConfig,
    ) -> Self {
        Self {
            pool,
            group_service,
            email,
            config,
        }
    }

    // ── Directed invites ─────────────────────────────────────────

    /// Admin creates + sends a directed invitation. Requires:
    /// (1) admin-token, (2) target address not already member or
    /// pending, (3) target address has a verified email binding.
    /// Returns the freshly-issued token, the email it was sent to,
    /// and the absolute expiry epoch-ms.
    pub async fn create_invitation(
        &self,
        group_id: Uuid,
        address: &str,
        admin_token: Option<&str>,
    ) -> Result<DirectedInvitationCreated, InvitationServiceError> {
        let group = self
            .group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let normalized =
            normalize_address(address).map_err(|_| InvitationServiceError::InvalidAddress)?;

        if let Some(existing) = bp_db::find_group_member_by_address(&self.pool, &normalized).await?
        {
            return Err(if existing.group_id == group_id {
                InvitationServiceError::AlreadyMember
            } else {
                InvitationServiceError::AddressInGroup
            });
        }

        let now = now_ms();
        let pending =
            bp_db::find_pplns_group_invitation_pending_directed(&self.pool, group_id, &normalized)
                .await?;
        if let Some(p) = &pending {
            if p.expires_at > now {
                return Err(InvitationServiceError::InvitationPending);
            }
        }

        // Email-verified binding is the trust anchor for the whole
        // invitation flow — without it an admin could silently route a
        // miner's payouts into their own group.
        let binding = bp_db::find_address_email(&self.pool, &normalized).await?;
        let binding = binding
            .filter(|b| b.verified_at.is_some())
            .ok_or(InvitationServiceError::EmailNotVerified)?;

        // Expire the stale pending row (if any) before inserting the new one.
        if let Some(p) = pending {
            if p.expires_at <= now {
                bp_db::update_pplns_group_invitation_status_by_token(
                    &self.pool, &p.token, "expired", None,
                )
                .await?;
            }
        }

        let token = InvitationToken::generate()?;
        let expires_at = now + invitation_ttl_ms();
        let row = bp_db::insert_pplns_group_invitation(
            &self.pool,
            token.as_str(),
            group_id,
            Some(&normalized),
            Some(&binding.email),
            InvitationKind::Directed.as_str(),
            /* approval_required = */ false,
            now,
            expires_at,
        )
        .await?;

        let base = self.require_base_url()?;
        let ctx = InvitationEmailContext {
            to_email: binding.email.clone(),
            address: normalized.as_str().to_string(),
            group_name: group.name.clone(),
            inviter_address: group.creator_address.as_str().to_string(),
            accept_url: format!("{base}/#/invite/{}", row.token),
            expires_at_ms: expires_at,
        };
        self.email.send_invitation(ctx).await;

        Ok(DirectedInvitationCreated {
            token: row.token,
            email: binding.email,
            expires_at,
        })
    }

    /// Public lookup of a directed invitation by its public token.
    /// Used by the accept/decline UI to render group context before
    /// the user commits. Returns `None` if the token belongs to an
    /// open invite, the group is dissolved, or the token is unknown.
    pub async fn get_by_token(
        &self,
        token: &str,
    ) -> Result<Option<(PplnsGroupInvitationRow, PplnsGroupRow)>, InvitationServiceError> {
        let invitation = bp_db::find_group_invitation(&self.pool, token).await?;
        let Some(invitation) = invitation else {
            return Ok(None);
        };
        if invitation.invite_type == InvitationKind::Open.as_str() {
            return Ok(None);
        }
        let group = bp_db::find_group(&self.pool, invitation.group_id).await?;
        let group = match group {
            Some(g) if g.dissolved_at.is_none() => g,
            _ => return Ok(None),
        };
        Ok(Some((invitation, group)))
    }

    /// Accept a directed invitation. Creates the member row (via
    /// [`GroupService::add_member_without_admin`]) and stamps the
    /// invitation `accepted`. Idempotent if the same token was already
    /// accepted into the same group.
    pub async fn accept(&self, token: &str) -> Result<PplnsGroupMemberRow, InvitationServiceError> {
        let invitation = bp_db::find_group_invitation(&self.pool, token)
            .await?
            .ok_or(InvitationServiceError::NotFound)?;
        if invitation.invite_type == InvitationKind::Open.as_str() {
            // Open invites flow through accept_open_invite(); refuse
            // the directed path silently.
            return Err(InvitationServiceError::NotFound);
        }
        // Status checks.
        match invitation.status.as_str() {
            "accepted" => {
                // Idempotent: the member row should still exist.
                let address = invitation
                    .address
                    .as_ref()
                    .ok_or(InvitationServiceError::Inconsistent)?;
                let member = bp_db::find_pplns_group_member_in_group(
                    &self.pool,
                    invitation.group_id,
                    address,
                )
                .await?;
                return member.ok_or(InvitationServiceError::Inconsistent);
            }
            "declined" => return Err(InvitationServiceError::AlreadyDeclined),
            "expired" | "revoked" => return Err(InvitationServiceError::Expired),
            _ => {}
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
            return Err(InvitationServiceError::Expired);
        }
        // Group dissolved between invite-send + accept?
        let group = bp_db::find_group(&self.pool, invitation.group_id).await?;
        let _group = match group {
            Some(g) if g.dissolved_at.is_none() => g,
            _ => return Err(InvitationServiceError::GroupDissolved),
        };

        let invited = invitation
            .address
            .as_ref()
            .ok_or(InvitationServiceError::Inconsistent)?;
        let normalized = normalize_address(invited.as_str())
            .map_err(|_| InvitationServiceError::InvalidAddress)?;

        // Defensive: address might have joined another group in the
        // meantime. Distinguish "into this group" (treat as idempotent
        // success) from "into another group" (clean error).
        let existing = bp_db::find_group_member_by_address(&self.pool, &normalized).await?;
        match existing {
            Some(m) if m.group_id != invitation.group_id => {
                return Err(InvitationServiceError::AddressInGroup);
            }
            Some(m) => {
                bp_db::update_pplns_group_invitation_status_by_token(
                    &self.pool,
                    &invitation.token,
                    "accepted",
                    Some(now),
                )
                .await?;
                return Ok(m);
            }
            None => {}
        }

        let member = self
            .group_service
            .add_member_without_admin(invitation.group_id, normalized.as_str())
            .await?;
        bp_db::update_pplns_group_invitation_status_by_token(
            &self.pool,
            &invitation.token,
            "accepted",
            Some(now),
        )
        .await?;
        Ok(member)
    }

    /// Decline a directed invitation. No auth — anyone with the token
    /// can decline (the token IS the proof of possession).
    pub async fn decline(&self, token: &str) -> Result<(), InvitationServiceError> {
        let invitation = bp_db::find_group_invitation(&self.pool, token)
            .await?
            .ok_or(InvitationServiceError::NotFound)?;
        if invitation.status == "pending" {
            let now = now_ms();
            bp_db::update_pplns_group_invitation_status_by_token(
                &self.pool,
                &invitation.token,
                "declined",
                Some(now),
            )
            .await?;
        }
        Ok(())
    }

    /// Public banner data — directed pending invitations for `address`.
    /// Deliberately excludes the token: the address holder accepts via
    /// the link delivered by email.
    pub async fn list_pending_for_address(
        &self,
        address: &str,
    ) -> Result<Vec<PendingForAddressView>, InvitationServiceError> {
        let normalized = match normalize_address(address) {
            Ok(a) => a,
            Err(_) => return Ok(Vec::new()),
        };
        let rows = bp_db::find_pplns_group_invitations_pending_for_address_directed(
            &self.pool,
            &normalized,
        )
        .await?;
        let now = now_ms();
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            if r.expires_at < now {
                continue;
            }
            let Some(group) = bp_db::find_group(&self.pool, r.group_id).await? else {
                continue;
            };
            if group.dissolved_at.is_some() {
                continue;
            }
            out.push(PendingForAddressView {
                group_id: r.group_id,
                group_name: group.name,
                inviter_address: group.creator_address,
                masked_email: r
                    .email
                    .as_deref()
                    .map(mask_email)
                    .unwrap_or_else(|| "—".to_string()),
                created_at: r.created_at,
                expires_at: r.expires_at,
            });
        }
        Ok(out)
    }

    /// Admin view — pending directed invitations for the group, raw
    /// rows. Past-`expiresAt` rows are filtered out so they don't show
    /// up before the cron sweeps them.
    pub async fn list_pending_for_group(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<PplnsGroupInvitationRow>, InvitationServiceError> {
        let rows =
            bp_db::find_pplns_group_invitations_pending_for_group_directed(&self.pool, group_id)
                .await?;
        let now = now_ms();
        Ok(rows.into_iter().filter(|r| r.expires_at >= now).collect())
    }

    /// Admin cancels a pending directed invitation by recipient
    /// address (admins never see the secret token).
    pub async fn cancel_invitation_by_address(
        &self,
        group_id: Uuid,
        address: &str,
        admin_token: Option<&str>,
    ) -> Result<(), InvitationServiceError> {
        self.group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let normalized =
            normalize_address(address).map_err(|_| InvitationServiceError::InvalidAddress)?;
        let invitation =
            bp_db::find_pplns_group_invitation_pending_directed(&self.pool, group_id, &normalized)
                .await?
                .ok_or(InvitationServiceError::NotFound)?;
        bp_db::delete_pplns_group_invitation_by_token(&self.pool, &invitation.token).await?;
        Ok(())
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
        let binding = bp_db::find_address_email(&self.pool, &normalized)
            .await?
            .filter(|b| b.verified_at.is_some())
            .ok_or(InvitationServiceError::EmailNotVerified)?;
        let _ = binding; // (kept for clarity; the email isn't carried over to the open row)

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

    // ── helpers ─────────────────────────────────────────────────

    fn require_base_url(&self) -> Result<&str, InvitationServiceError> {
        self.config
            .pool_base_url
            .as_deref()
            .map(|s| s.trim_end_matches('/'))
            .ok_or(InvitationServiceError::ConfigMissing)
    }
}

/// Mask an email for public surfacing: first char of the local part plus
/// first char of the domain, TLD kept (e.g. `foo@bar.com` → `f***@b***.com`).
/// Obscuring the domain head keeps a custom/vanity domain from pinpointing
/// identity. Malformed / TLD-less inputs collapse to `***` forms.
fn mask_email(email: &str) -> String {
    if email.is_empty() {
        return String::new();
    }
    let Some(at_idx) = email.find('@') else {
        return "***".to_owned();
    };
    if at_idx == 0 || at_idx == email.len() - 1 {
        return "***".to_owned();
    }
    let local_head = email[..at_idx].chars().next().unwrap_or('?');
    let domain = &email[at_idx + 1..];
    let Some(dot_idx) = domain.find('.') else {
        return format!("{local_head}***@***");
    };
    if dot_idx == 0 {
        return format!("{local_head}***@***");
    }
    let domain_head = domain.chars().next().unwrap_or('?');
    let tld_and_below = &domain[dot_idx..];
    format!("{local_head}***@{domain_head}***{tld_and_below}")
}

/// Logged-only no-op for callers that want a non-async helper to
/// degrade gracefully when a hook side-effect fails.
#[allow(dead_code)]
fn log_swallowed_warn(label: &str, err: impl std::fmt::Display) {
    warn!("[invitation] {label} failed: {err}");
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

    #[test]
    fn mask_email_obscures_local_and_domain_head() {
        assert_eq!(mask_email("foo@bar.com"), "f***@b***.com");
        assert_eq!(mask_email("a@x.io"), "a***@x***.io");
        assert_eq!(mask_email("alice@gmail.com"), "a***@g***.com");
        assert_eq!(mask_email("user@localhost"), "u***@***");
        assert_eq!(mask_email("@y.io"), "***");
        assert_eq!(mask_email("garbage"), "***");
    }
}
