// SPDX-License-Identifier: AGPL-3.0-or-later

//! Blockparty invitation service — directed-invite-only (no open links,
//! no join-request flow).
//!
//! Reuses:
//!   - `bp_group_mgmt::token::InvitationToken` (CSPRNG-backed)
//!   - `bp_group_mgmt_engine::EmailHooks` trait (same shape, different
//!     URL template — the trait owner picks the template)
//!
//! Wraps `BlockpartyService` for the state-management calls so the
//! routing-cache stays in sync after accepts / resends.

use std::sync::Arc;

use bp_blockparty::DEFAULT_INVITATION_TTL_DAYS;
use bp_db::{BlockpartyGroupRow, BlockpartyInvitationRow};
use bp_group_mgmt::token::InvitationToken;
use bp_group_mgmt_engine::{EmailHooks, InvitationEmailContext};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{BlockpartyInvitationServiceError, BlockpartyServiceError};
use crate::hooks::BlockpartyHooks;
use crate::service::BlockpartyService;
use crate::util::{normalize_address, now_ms};

const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug)]
pub struct BlockpartyInvitationServiceConfig {
    /// Public-facing UI URL — used to build the accept link. Falls back
    /// to "config-missing" error when None and an invitation is being
    /// created (the public read paths don't need it).
    pub pool_base_url: Option<String>,
}

#[derive(Debug)]
pub struct DirectedInvitationCreated {
    /// Bearer token — included in the email URL. Never serialised back
    /// to the admin response (UI shows "invitation sent to <email>"
    /// only; the token stays out-of-band).
    pub token: String,
    pub email: String,
    pub expires_at_ms: i64,
    /// Returned so the admin UI can render "resent" vs "newly issued"
    /// without comparing timestamps.
    pub resent: bool,
}

pub struct BlockpartyInvitationService<H: BlockpartyHooks, M: EmailHooks> {
    pool: PgPool,
    service: Arc<BlockpartyService<H>>,
    email: Arc<M>,
    config: BlockpartyInvitationServiceConfig,
}

impl<H: BlockpartyHooks, M: EmailHooks> BlockpartyInvitationService<H, M> {
    pub fn new(
        pool: PgPool,
        service: Arc<BlockpartyService<H>>,
        email: Arc<M>,
        config: BlockpartyInvitationServiceConfig,
    ) -> Self {
        Self {
            pool,
            service,
            email,
            config,
        }
    }

    fn require_base_url(&self) -> Result<&str, BlockpartyInvitationServiceError> {
        self.config
            .pool_base_url
            .as_deref()
            .ok_or(BlockpartyInvitationServiceError::ConfigMissing)
    }

    // ─── Public reads ──────────────────────────────────────────────

    /// Public read for the invite landing page. Returns invitation +
    /// group so the UI can show the deal before accept.
    pub async fn get_by_token(
        &self,
        token: &str,
    ) -> Result<
        Option<(BlockpartyInvitationRow, BlockpartyGroupRow)>,
        BlockpartyInvitationServiceError,
    > {
        let Some(inv) = bp_db::find_blockparty_invitation_by_token(&self.pool, token).await? else {
            return Ok(None);
        };
        let Some(group) = bp_db::find_blockparty_group(&self.pool, inv.group_id).await? else {
            return Ok(None);
        };
        if group.status == bp_blockparty::BlockpartyStatus::Dissolved.as_str() {
            return Ok(None);
        }
        Ok(Some((inv, group)))
    }

    pub async fn list_for_group(
        &self,
        group_id: Uuid,
        admin_token: Option<&str>,
    ) -> Result<Vec<BlockpartyInvitationRow>, BlockpartyInvitationServiceError> {
        let _gated = self
            .service
            .require_admin_token(group_id, admin_token)
            .await?;
        Ok(bp_db::list_blockparty_invitations_for_group(&self.pool, group_id).await?)
    }

    // ─── Admin-gated mutations ─────────────────────────────────────

    /// Issue a directed invitation. Admin-gated. Pulls verified email
    /// via the hook (admin doesn't supply email; binding is the trust
    /// anchor). One row per `(group_id, address)` — pending rows are
    /// reused, the partial unique index in PG enforces this at the DB
    /// layer too.
    pub async fn create_invitation(
        &self,
        group_id: Uuid,
        address: &str,
        ttl_days: Option<i64>,
        admin_token: Option<&str>,
    ) -> Result<DirectedInvitationCreated, BlockpartyInvitationServiceError> {
        let group = self
            .service
            .require_admin_token(group_id, admin_token)
            .await?;
        let normalized = normalize_address(address)?;

        // Member row must already exist — addMember inserts it, then
        // createInvitation mints the token + sends mail.
        let member = bp_db::find_blockparty_member_in_group(&self.pool, group_id, &normalized)
            .await?
            .ok_or_else(|| {
                BlockpartyInvitationServiceError::Service(BlockpartyServiceError::NotMember)
            })?;
        // Already-confirmed members don't need a new invitation. The
        // admin uses resendInvitation (with reset_member_onboarding)
        // to recover a lost member-token instead.
        if member.confirmed_at.is_some() {
            return Err(BlockpartyInvitationServiceError::AlreadyMember);
        }
        let _ = member; // consume the row; we only needed the confirmed_at check

        let email = self
            .service
            .hooks()
            .verified_email_for(&normalized)
            .await
            .ok_or(BlockpartyInvitationServiceError::EmailNotVerified)?;

        let now = now_ms();
        let ttl_days = ttl_days.unwrap_or(DEFAULT_INVITATION_TTL_DAYS).max(1);
        let expires_at = now + ttl_days * MS_PER_DAY;

        // Pending-row reuse: without this every resend would mint a
        // fresh row and the admin UI would show duplicate pending
        // entries for the same (group, address) pair.
        let pending = bp_db::find_blockparty_invitation_pending_for_group_address(
            &self.pool,
            group_id,
            &normalized,
        )
        .await?;
        let (row_token, resent) = if let Some(p) = pending {
            if p.expires_at > now {
                // Live pending — reuse same token, just resend email.
                (p.token, true)
            } else {
                // Stale pending — flip to expired so the new insert
                // doesn't trip the partial unique index, then mint.
                bp_db::update_blockparty_invitation_status(
                    &self.pool,
                    &p.token,
                    "expired",
                    Some(now),
                )
                .await?;
                let fresh = InvitationToken::generate()?;
                let inserted = bp_db::insert_blockparty_invitation(
                    &self.pool,
                    fresh.as_str(),
                    group_id,
                    &normalized,
                    &email,
                    now,
                    expires_at,
                )
                .await?;
                (inserted.token, false)
            }
        } else {
            let fresh = InvitationToken::generate()?;
            let inserted = bp_db::insert_blockparty_invitation(
                &self.pool,
                fresh.as_str(),
                group_id,
                &normalized,
                &email,
                now,
                expires_at,
            )
            .await?;
            (inserted.token, false)
        };

        // EmailHooks is best-effort fire-and-forget — SMTP failures
        // stay in the adapter's log and the admin can resend. The
        // only error surfaced here is config-missing for the base URL,
        // caught above.
        let base = self.require_base_url()?;
        let ctx = InvitationEmailContext {
            to_email: email.clone(),
            address: normalized.as_str().to_owned(),
            group_name: group.name.clone(),
            inviter_address: group.admin_address.as_str().to_owned(),
            accept_url: format!("{base}/#/blockparty/invite/{row_token}"),
            expires_at_ms: expires_at,
        };
        self.email.send_invitation(ctx).await;

        Ok(DirectedInvitationCreated {
            token: row_token,
            email,
            expires_at_ms: expires_at,
            resent,
        })
    }

    /// Re-send a directed invitation. Three cases:
    ///   1. Pending non-expired → reuse same token, resend email
    ///   2. Pending-but-expired → mint fresh, send
    ///   3. No pending → mint fresh, send
    ///
    /// Lost-token recovery: clears the member's `member_token_hash` +
    /// `confirmedAt` so the next accept mints a fresh persistent
    /// member token. Without this a member who lost their token has
    /// no way to recover.
    pub async fn resend_invitation(
        &self,
        group_id: Uuid,
        address: &str,
        ttl_days: Option<i64>,
        admin_token: Option<&str>,
    ) -> Result<DirectedInvitationCreated, BlockpartyInvitationServiceError> {
        // Reset onboarding so the next accept mints a fresh member
        // token. Calls into service so cache + state are kept in sync.
        let normalized = normalize_address(address)?;
        self.service
            .reset_member_onboarding(group_id, &normalized)
            .await?;
        // Delegating to create_invitation handles cases 1/2/3 inside
        // the same SQL transaction-window. Returns `resent=true` for
        // case 1, `false` for cases 2/3.
        self.create_invitation(group_id, address, ttl_days, admin_token)
            .await
    }

    /// Revoke a pending invitation. Admin-gated. Flips it to expired
    /// so it can no longer be accepted and frees the (groupId, address)
    /// slot for a fresh issue.
    pub async fn revoke(
        &self,
        group_id: Uuid,
        token: &str,
        admin_token: Option<&str>,
    ) -> Result<(), BlockpartyInvitationServiceError> {
        let _gated = self
            .service
            .require_admin_token(group_id, admin_token)
            .await?;
        let invitation = bp_db::find_blockparty_invitation_by_token(&self.pool, token)
            .await?
            .ok_or(BlockpartyInvitationServiceError::NotFound)?;
        if invitation.group_id != group_id {
            return Err(BlockpartyInvitationServiceError::NotFound);
        }
        if invitation.status != "pending" {
            return Err(BlockpartyInvitationServiceError::NotPending);
        }
        let affected = bp_db::update_blockparty_invitation_status(
            &self.pool,
            token,
            "expired",
            Some(now_ms()),
        )
        .await?;
        if affected == 0 {
            return Err(BlockpartyInvitationServiceError::NotFound);
        }
        Ok(())
    }

    // ─── Public-token endpoints ────────────────────────────────────

    /// Accept an invitation. Public — the token IS the auth. Marks the
    /// invitation accepted, then mints (or reuses) the persistent
    /// member token via `mark_member_confirmed` (which also fires the
    /// status recompute + routing-cache sync).
    pub async fn accept(
        &self,
        token: &str,
    ) -> Result<crate::service::MarkMemberConfirmedResult, BlockpartyInvitationServiceError> {
        let invitation = bp_db::find_blockparty_invitation_by_token(&self.pool, token)
            .await?
            .ok_or(BlockpartyInvitationServiceError::NotFound)?;
        if invitation.status != "pending" {
            return Err(BlockpartyInvitationServiceError::NotPending);
        }
        let now = now_ms();
        if invitation.expires_at <= now {
            // Auto-expire the row so future reads see the right state.
            let _ =
                bp_db::update_blockparty_invitation_status(&self.pool, token, "expired", Some(now))
                    .await;
            return Err(BlockpartyInvitationServiceError::Expired);
        }
        let group = bp_db::find_blockparty_group(&self.pool, invitation.group_id)
            .await?
            .ok_or(BlockpartyInvitationServiceError::NotFound)?;
        if group.status == bp_blockparty::BlockpartyStatus::Dissolved.as_str() {
            return Err(BlockpartyInvitationServiceError::GroupDissolved);
        }

        // Mark accepted FIRST (cheap) — if the mark_member_confirmed
        // call below fails, the admin's view shows the invitation as
        // accepted-but-not-confirmed, which is a recoverable state
        // (admin can resend with reset_onboarding to retry).
        bp_db::update_blockparty_invitation_status(&self.pool, token, "accepted", Some(now))
            .await?;
        let confirmed = self
            .service
            .mark_member_confirmed(invitation.group_id, &invitation.address)
            .await?;
        Ok(confirmed)
    }

    /// Decline an invitation. Public — the token IS the auth.
    pub async fn decline(&self, token: &str) -> Result<(), BlockpartyInvitationServiceError> {
        let invitation = bp_db::find_blockparty_invitation_by_token(&self.pool, token)
            .await?
            .ok_or(BlockpartyInvitationServiceError::NotFound)?;
        if invitation.status != "pending" {
            return Err(BlockpartyInvitationServiceError::NotPending);
        }
        let _ = bp_db::update_blockparty_invitation_status(
            &self.pool,
            token,
            "declined",
            Some(now_ms()),
        )
        .await?;
        Ok(())
    }
}
