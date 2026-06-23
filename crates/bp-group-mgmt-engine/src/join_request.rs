// SPDX-License-Identifier: AGPL-3.0-or-later

//! User-initiated request to join a *public* group. The complement to
//! invitations:
//!
//! - **Invitation**: admin → specific address (directed) or shareable
//!   link (open). Admin-initiated.
//! - **Join request**: user → group. Admin reviews + approves/rejects.
//!
//! Trust anchor is the same as for invitations — the requesting
//! address must have a verified email binding (snapshotted on the
//! request row so approve/reject mail reaches the right inbox even if
//! the user later rebinds).

use std::sync::Arc;

use bp_common::AddressId;
use bp_db::PplnsGroupJoinRequestRow;
use bp_group_mgmt::token::TokenHash;
use sqlx::PgPool;
use uuid::Uuid;

use crate::email_hooks::{EmailHooks, JoinDecisionEmailContext, JoinDecisionOutcome};
use crate::error::JoinRequestServiceError;
use crate::hooks::GroupServiceHooks;
use crate::service::GroupService;
use crate::util::{normalize_address, now_ms};

/// Multi-layer caps for join requests.
#[derive(Debug, Clone, Copy)]
pub struct JoinRequestLimits {
    /// Maximum simultaneously-pending join requests for one address
    /// across **all** groups. Default = 10.
    pub max_pending_per_address: u32,
    /// Hours of cooldown after a rejected (group, address) pair
    /// before a fresh request is allowed. Default = 24.
    pub reject_cooldown_hours: u32,
}

impl Default for JoinRequestLimits {
    fn default() -> Self {
        Self {
            max_pending_per_address: 10,
            reject_cooldown_hours: 24,
        }
    }
}

/// Configuration shared across join-request paths — base URL for the
/// approve/reject decision emails.
#[derive(Debug, Default, Clone)]
pub struct JoinRequestServiceConfig {
    pub pool_base_url: Option<String>,
    pub limits: JoinRequestLimits,
}

/// Public-banner view of one of the requester's own pending requests.
#[derive(Debug, Clone)]
pub struct PendingForAddressView {
    pub group_id: Uuid,
    pub group_name: String,
    pub created_at: i64,
}

/// Top-level join-request service.
#[derive(Clone)]
pub struct JoinRequestService<H: GroupServiceHooks, M: EmailHooks> {
    pool: PgPool,
    group_service: Arc<GroupService<H>>,
    email: Arc<M>,
    config: JoinRequestServiceConfig,
}

impl<H: GroupServiceHooks, M: EmailHooks> JoinRequestService<H, M> {
    pub fn new(
        pool: PgPool,
        group_service: Arc<GroupService<H>>,
        email: Arc<M>,
        config: JoinRequestServiceConfig,
    ) -> Self {
        Self {
            pool,
            group_service,
            email,
            config,
        }
    }

    /// Create a join request. Public — no admin token. Multi-step
    /// validation:
    ///
    /// 1. Group exists, is public, not dissolved.
    /// 2. Address shape valid + has a verified email binding.
    /// 3. Address isn't already a member of any group.
    /// 4. Address isn't over the global pending cap.
    /// 5. No (group, address) row currently in cooldown.
    /// 6. The DB unique partial index on `(groupId, address) WHERE
    ///    status='pending'` does the final consistency check; a 23505
    ///    is surfaced as [`JoinRequestServiceError::RequestPending`].
    pub async fn create_join_request(
        &self,
        group_id: Uuid,
        address: &str,
        message: Option<&str>,
    ) -> Result<PplnsGroupJoinRequestRow, JoinRequestServiceError> {
        // (1) Group must exist, be public, not dissolved. We don't
        // distinguish private-but-exists vs not-found
        // ("don't leak existence of private groups").
        let group = bp_db::find_group(&self.pool, group_id).await?;
        let group = match group {
            Some(g) if g.dissolved_at.is_none() && g.is_public => g,
            _ => return Err(JoinRequestServiceError::NotFound),
        };

        // (2) Validate + normalize address shape.
        let normalized =
            normalize_address(address).map_err(|_| JoinRequestServiceError::InvalidAddress)?;
        let binding = bp_db::find_address_email(&self.pool, &normalized)
            .await?
            .filter(|b| b.verified_at.is_some())
            .ok_or(JoinRequestServiceError::EmailNotVerified)?;

        // (3) Already a member?
        if let Some(existing) = bp_db::find_group_member_by_address(&self.pool, &normalized).await?
        {
            return Err(if existing.group_id == group_id {
                JoinRequestServiceError::AlreadyMember
            } else {
                JoinRequestServiceError::AddressInGroup
            });
        }

        // (4) Global pending cap.
        let pending =
            bp_db::count_pplns_group_join_requests_pending_for_address(&self.pool, &normalized)
                .await?;
        if pending as u32 >= self.config.limits.max_pending_per_address {
            return Err(JoinRequestServiceError::TooManyPending);
        }

        // (5) Reject cooldown — block if the same (group, address)
        // was rejected within `reject_cooldown_hours`.
        let recent_reject = bp_db::find_pplns_group_join_request_most_recent_rejected(
            &self.pool,
            group_id,
            &normalized,
        )
        .await?;
        if let Some(r) = recent_reject {
            if let Some(decided_at) = r.decided_at {
                let now = now_ms();
                let elapsed_h = (now - decided_at) as f64 / (60.0 * 60.0 * 1000.0);
                if elapsed_h < self.config.limits.reject_cooldown_hours as f64 {
                    let hours_left =
                        (self.config.limits.reject_cooldown_hours as f64 - elapsed_h).ceil() as u32;
                    return Err(JoinRequestServiceError::RejectCooldown { hours_left });
                }
            }
        }

        // (6) Trim + cap message. An over-long body is silently truncated.
        let trimmed = message
            .map(|m| m.trim())
            .filter(|m| !m.is_empty())
            .map(|m| {
                let cap = bp_group_mgmt::constants::MAX_JOIN_REQUEST_MESSAGE_LEN;
                if m.len() > cap {
                    // Back off to a UTF-8 char boundary so a multibyte char
                    // straddling the cap can't panic the slice.
                    let mut end = cap;
                    while !m.is_char_boundary(end) {
                        end -= 1;
                    }
                    m[..end].to_string()
                } else {
                    m.to_string()
                }
            });

        let now = now_ms();
        match bp_db::insert_pplns_group_join_request(
            &self.pool,
            group.id,
            &normalized,
            &binding.email,
            trimmed.as_deref(),
            now,
        )
        .await
        {
            Ok(row) => Ok(row),
            Err(e) => {
                if is_unique_violation(&e) {
                    Err(JoinRequestServiceError::RequestPending)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Admin list of join requests. Default returns only pending;
    /// pass `include_decided=true` for audit views.
    pub async fn list_for_group(
        &self,
        group_id: Uuid,
        admin_token: Option<&str>,
        include_decided: bool,
    ) -> Result<Vec<PplnsGroupJoinRequestRow>, JoinRequestServiceError> {
        self.group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        Ok(
            bp_db::list_pplns_group_join_requests_for_group(&self.pool, group_id, include_decided)
                .await?,
        )
    }

    /// Approve a pending request. Creates the membership via
    /// [`GroupService::add_member_without_admin`] (which itself
    /// guards against the address joining another group in the
    /// meantime). Emits a best-effort approval email.
    pub async fn approve_request(
        &self,
        group_id: Uuid,
        request_id: Uuid,
        admin_token: Option<&str>,
    ) -> Result<(), JoinRequestServiceError> {
        let group = self
            .group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let request =
            bp_db::find_pplns_group_join_request_pending_in_group(&self.pool, request_id, group_id)
                .await?
                .ok_or(JoinRequestServiceError::NotFound)?;
        if group.dissolved_at.is_some() {
            return Err(JoinRequestServiceError::GroupDissolved);
        }

        let address = request.address.clone();
        let admin_hash = TokenHash::of_str(admin_token.unwrap_or(""));
        let now = now_ms();

        // Last-mile membership check: address might have joined
        // another group between request + approval. Mark rejected
        // (audit) so the admin doesn't keep seeing it.
        let existing = bp_db::find_group_member_by_address(&self.pool, &address).await?;
        if let Some(m) = &existing {
            if m.group_id != group_id {
                bp_db::update_pplns_group_join_request_decision(
                    &self.pool,
                    request.id,
                    "rejected",
                    now,
                    admin_hash.as_str(),
                )
                .await?;
                return Err(JoinRequestServiceError::AddressInGroup);
            }
        }
        if existing.is_none() {
            self.group_service
                .add_member_without_admin(group_id, address.as_str())
                .await?;
        }
        bp_db::update_pplns_group_join_request_decision(
            &self.pool,
            request.id,
            "approved",
            now,
            admin_hash.as_str(),
        )
        .await?;

        if let Some(base) = self.config.pool_base_url.as_deref() {
            let url = format!(
                "{}/#/app/{}/payout-group",
                base.trim_end_matches('/'),
                address.as_str()
            );
            self.email
                .send_join_decision(JoinDecisionEmailContext {
                    to_email: request.email,
                    address: address.as_str().to_string(),
                    group_name: group.name,
                    outcome: JoinDecisionOutcome::Approved,
                    group_url: url,
                })
                .await;
        }
        Ok(())
    }

    /// Reject a pending request. Emits a best-effort rejection email.
    pub async fn reject_request(
        &self,
        group_id: Uuid,
        request_id: Uuid,
        admin_token: Option<&str>,
    ) -> Result<(), JoinRequestServiceError> {
        let group = self
            .group_service
            .require_admin_token(group_id, admin_token)
            .await?;
        let request =
            bp_db::find_pplns_group_join_request_pending_in_group(&self.pool, request_id, group_id)
                .await?
                .ok_or(JoinRequestServiceError::NotFound)?;

        let admin_hash = TokenHash::of_str(admin_token.unwrap_or(""));
        let now = now_ms();
        bp_db::update_pplns_group_join_request_decision(
            &self.pool,
            request.id,
            "rejected",
            now,
            admin_hash.as_str(),
        )
        .await?;

        if let Some(base) = self.config.pool_base_url.as_deref() {
            let url = format!("{}/#/groups/public", base.trim_end_matches('/'));
            self.email
                .send_join_decision(JoinDecisionEmailContext {
                    to_email: request.email,
                    address: request.address.as_str().to_string(),
                    group_name: group.name,
                    outcome: JoinDecisionOutcome::Rejected,
                    group_url: url,
                })
                .await;
        }
        Ok(())
    }

    /// Public banner data — one address's pending requests, across
    /// all groups. Drives the "you have a request pending" badge in
    /// the public directory.
    pub async fn list_for_address(
        &self,
        address: &str,
    ) -> Result<Vec<PendingForAddressView>, JoinRequestServiceError> {
        let normalized = match normalize_address(address) {
            Ok(a) => a,
            Err(_) => return Ok(Vec::new()),
        };
        let rows =
            bp_db::list_pplns_group_join_requests_pending_for_address(&self.pool, &normalized)
                .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let Some(group) = bp_db::find_group(&self.pool, r.group_id).await? else {
                continue;
            };
            if group.dissolved_at.is_some() {
                continue;
            }
            out.push(PendingForAddressView {
                group_id: r.group_id,
                group_name: group.name,
                created_at: r.created_at,
            });
        }
        Ok(out)
    }
}

/// Inspect a `DbError` for the Postgres unique-violation SQLSTATE
/// (`23505`).
fn is_unique_violation(err: &bp_db::DbError) -> bool {
    use bp_db::DbError;
    match err {
        DbError::Sqlx(sqlx::Error::Database(db_err)) => db_err.code().as_deref() == Some("23505"),
        _ => false,
    }
}

/// AddressId fwd-ref to keep clippy happy about the unused import — not
/// strictly needed but mirrors the style other modules use.
#[allow(dead_code)]
fn _force_address_id_use(_: AddressId) {}
