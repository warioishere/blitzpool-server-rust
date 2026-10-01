// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production impls of the Noop-by-default hook traits of bp-api and the
//! group-mgmt engine: verification, invitation and join-decision emails, and
//! the Group-Solo last-active lookup plus kick / dissolve Redis cleanup.

use std::sync::Arc;

use async_trait::async_trait;
use bp_api::email_hooks::{
    BindingChangeContext as ApiBindingChangeContext, EmailVerificationHooks,
    VerificationContext as ApiVerificationContext,
};
use bp_common::AddressId;
use bp_config::AppConfig;
use bp_db::Db;
use bp_db::{delete_pplns_group_block_history_for_group, PplnsGroupRow};
use bp_group_mgmt_engine::{
    EmailHooks, GroupServiceHooks, JoinDecisionEmailContext, JoinDecisionOutcome,
};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_notifications::adapter::{
    AdapterError, FcmAdapter, FcmConfig, FcmServiceAccount, SmtpAdapter,
    SmtpConfig as NotifSmtpConfig, VapidConfig, WebPushAdapter,
};
use bp_notifications::template::{
    render_binding_change, render_join_decision, render_verification,
    BindingChangeContext as TplBindingChangeContext, JoinDecision as TplJoinDecision,
    JoinDecisionContext as TplJoinDecisionContext, VerificationContext as TplVerificationContext,
};
use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;

/// Every production hook impl, handed to the bp-api `AppState` and the
/// engine wiring. The SMTP wrapper holds an `Option`, so one type serves
/// with and without `[smtp]`.
pub(crate) struct ProductionHooks {
    pub(crate) email_verification: Arc<dyn EmailVerificationHooks>,
    pub(crate) invitation_email: Arc<SmtpInvitationEmailHooks>,
    pub(crate) group_service: Arc<ProductionGroupServiceHooks>,
    /// FCM adapter for the crons. `None` without `[notifications.fcm]`; the
    /// network-difficulty cron then keeps its tracker row fresh without push.
    pub(crate) fcm: Option<Arc<FcmAdapter>>,
    /// Web-Push adapter for the `NotificationDispatcher`. `None` when
    /// `[notifications.web_push]` is not configured.
    pub(crate) web_push: Option<Arc<WebPushAdapter>>,
}

#[derive(Debug, Error)]
pub(crate) enum HooksError {
    #[error("smtp adapter init failed: {0}")]
    Smtp(AdapterError),
    #[error("fcm adapter init failed: {0}")]
    Fcm(AdapterError),
    #[error("fcm service-account JSON read failed at {path}: {source}")]
    FcmIo {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("web-push adapter init failed: {0}")]
    WebPush(AdapterError),
}

/// Build every production hook from `cfg` and the live handles. Bad
/// adapter config is a boot-time error, not a runtime failure.
pub(crate) async fn spawn(
    cfg: &AppConfig,
    foundation: &FoundationHandles,
    engines: &EngineHandles,
) -> Result<ProductionHooks, HooksError> {
    let smtp = build_smtp_adapter(cfg)?;
    let fcm = build_fcm_adapter(cfg)?;
    let web_push = build_web_push_adapter(cfg)?;

    let pool_base_url = cfg.pool_base_url.clone();
    let email_verification: Arc<dyn EmailVerificationHooks> =
        Arc::new(SmtpEmailVerificationHooks::new(smtp.clone()));
    let invitation_email = Arc::new(SmtpInvitationEmailHooks::new(smtp.clone()));
    let group_service = Arc::new(ProductionGroupServiceHooks {
        db: foundation.db.clone(),
        group_solo: engines.group_solo.clone(),
    });

    info!(
        smtp_ready = smtp.is_some(),
        fcm_ready = fcm.is_some(),
        web_push_ready = web_push.is_some(),
        pool_base_url_set = pool_base_url.is_some(),
        "production hooks ready"
    );
    Ok(ProductionHooks {
        email_verification,
        invitation_email,
        group_service,
        fcm,
        web_push,
    })
}

// ─── Adapter builders ────────────────────────────────────────────

fn build_smtp_adapter(cfg: &AppConfig) -> Result<Option<Arc<SmtpAdapter>>, HooksError> {
    let Some(smtp) = cfg.smtp.as_ref() else {
        warn!("smtp: not configured — verification + invitation emails will silently no-op");
        return Ok(None);
    };
    let notif_cfg = NotifSmtpConfig {
        host: smtp.host.clone(),
        port: smtp.port,
        secure: smtp.secure,
        user: smtp.user.clone(),
        pass: smtp.pass.clone(),
        from: smtp.from.clone(),
        reply_to: None,
        unsubscribe_mailto: None,
    };
    let adapter = SmtpAdapter::new(notif_cfg).map_err(HooksError::Smtp)?;
    info!(host = %smtp.host, port = smtp.port, secure = smtp.secure, "smtp: adapter ready");
    Ok(Some(Arc::new(adapter)))
}

fn build_fcm_adapter(cfg: &AppConfig) -> Result<Option<Arc<FcmAdapter>>, HooksError> {
    let Some(fcm_cfg) = cfg.notifications.fcm.as_ref() else {
        return Ok(None);
    };
    let path = &fcm_cfg.service_account_path;
    let json = std::fs::read_to_string(path).map_err(|source| HooksError::FcmIo {
        path: path.clone(),
        source,
    })?;
    let service_account = FcmServiceAccount::from_json(&json).map_err(HooksError::Fcm)?;
    let adapter = FcmAdapter::new(FcmConfig { service_account }).map_err(HooksError::Fcm)?;
    info!(path = %path.display(), "fcm: adapter ready");
    Ok(Some(Arc::new(adapter)))
}

fn build_web_push_adapter(cfg: &AppConfig) -> Result<Option<Arc<WebPushAdapter>>, HooksError> {
    let Some(wp) = cfg.notifications.web_push.as_ref() else {
        return Ok(None);
    };
    let adapter = WebPushAdapter::new(Some(VapidConfig {
        private_key_b64url: wp.vapid_private_key.clone(),
        public_key_b64url: wp.vapid_public_key.clone(),
        subject: wp.vapid_subject.clone(),
    }))
    .map_err(HooksError::WebPush)?;
    info!(subject = %wp.vapid_subject, "web-push: adapter ready (VAPID)");
    Ok(Some(Arc::new(adapter)))
}

// ─── EmailVerificationHooks impl ─────────────────────────────────

/// SMTP-backed email-verification hook. Without `[smtp]` every method is a
/// quiet no-op, so the verify-email path disables itself instead of
/// failing requests.
pub(crate) struct SmtpEmailVerificationHooks {
    smtp: Option<Arc<SmtpAdapter>>,
}

impl SmtpEmailVerificationHooks {
    pub(crate) fn new(smtp: Option<Arc<SmtpAdapter>>) -> Self {
        Self { smtp }
    }
}

#[async_trait]
impl EmailVerificationHooks for SmtpEmailVerificationHooks {
    async fn send_verification(&self, ctx: ApiVerificationContext) {
        let Some(smtp) = self.smtp.as_ref() else {
            return;
        };
        let tpl_ctx = TplVerificationContext {
            address: ctx.address.clone(),
            verify_url: ctx.verify_url.clone(),
            expires_at: epoch_ms_to_utc(ctx.expires_at_ms),
        };
        let content = render_verification(&tpl_ctx);
        if let Err(err) = smtp.send_email(&ctx.to_email, &content).await {
            warn!(
                %err,
                to = %ctx.to_email,
                address = %ctx.address,
                "smtp: send_verification failed (best-effort)"
            );
        }
    }

    async fn send_binding_change_attempt(&self, ctx: ApiBindingChangeContext) {
        let Some(smtp) = self.smtp.as_ref() else {
            return;
        };
        let tpl_ctx = TplBindingChangeContext {
            address: ctx.address.clone(),
            attempted_email_masked: ctx.attempted_email_masked.clone(),
        };
        let content = render_binding_change(&tpl_ctx);
        if let Err(err) = smtp.send_email(&ctx.to_email, &content).await {
            warn!(
                %err,
                to = %ctx.to_email,
                address = %ctx.address,
                "smtp: send_binding_change failed (best-effort)"
            );
        }
    }
}

// ─── bp-group-mgmt-engine::EmailHooks impl ───────────────────────

/// SMTP-backed invitation + join-decision email hook; like
/// [`SmtpEmailVerificationHooks`], a quiet no-op without SMTP.
pub(crate) struct SmtpInvitationEmailHooks {
    smtp: Option<Arc<SmtpAdapter>>,
}

impl SmtpInvitationEmailHooks {
    pub(crate) fn new(smtp: Option<Arc<SmtpAdapter>>) -> Self {
        Self { smtp }
    }
}

#[async_trait]
impl EmailHooks for SmtpInvitationEmailHooks {
    async fn send_join_decision(&self, ctx: JoinDecisionEmailContext) {
        let Some(smtp) = self.smtp.as_ref() else {
            return;
        };
        let decision = match ctx.outcome {
            JoinDecisionOutcome::Approved => TplJoinDecision::Approved,
            JoinDecisionOutcome::Rejected => TplJoinDecision::Rejected,
        };
        let tpl_ctx = TplJoinDecisionContext {
            address: ctx.address.clone(),
            group_name: ctx.group_name.clone(),
            group_url: ctx.group_url.clone(),
        };
        let content = render_join_decision(&tpl_ctx, decision);
        if let Err(err) = smtp.send_email(&ctx.to_email, &content).await {
            warn!(
                %err,
                to = %ctx.to_email,
                address = %ctx.address,
                group = %ctx.group_name,
                outcome = ?ctx.outcome,
                "smtp: send_join_decision failed (best-effort)"
            );
        }
    }
}

// ─── bp-group-mgmt-engine::GroupServiceHooks impl ────────────────

pub(crate) struct ProductionGroupServiceHooks {
    db: Db,
    group_solo: GroupSoloEngine,
}

#[async_trait]
impl GroupServiceHooks for ProductionGroupServiceHooks {
    async fn last_active_for_member(&self, group_id: Uuid, address: &AddressId) -> Option<i64> {
        // Redis is the only source (Group-Solo keeps no ledger row). `None`
        // makes the caller fall back to `joined_at`, so after a Redis loss a
        // long-standing member looks freshly joined.
        let group_key = group_id.to_string();
        match self
            .group_solo
            .round()
            .read_last_accepted_share_at(&group_key, address.as_str())
            .await
        {
            Ok(ts) => ts,
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    address = %address.as_str(),
                    "group-hooks: last_active_for_member redis read failed — reporting \
                     'never mined', which lets the kick-inactivity guard fall back to joinedAt"
                );
                None
            }
        }
    }

    async fn on_member_removed(
        &self,
        group_id: Uuid,
        kicked_address: &AddressId,
        _remaining_addresses: &[AddressId],
    ) {
        // Redis: drop the address from the payout source of the group's
        // mode (PROP round or both window lanes), its reject counter, the
        // inactivity clock and, if it was theirs, the best share.
        match self
            .group_solo
            .forget_member(group_id, kicked_address.as_str())
            .await
        {
            Ok(removed_diff) => {
                info!(
                    %group_id,
                    address = %kicked_address.as_str(),
                    removed_diff,
                    "group-hooks: on_member_removed redis cleanup ok"
                );
            }
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    address = %kicked_address.as_str(),
                    "group-hooks: on_member_removed redis cleanup failed (best-effort)"
                );
            }
        }

        // Nothing to settle in Postgres: `forget_member` removed their
        // shares from the round, so the next distribution splits between
        // whoever is left. That is the redistribution.
    }

    async fn on_group_dissolved(&self, group_id: Uuid) {
        let group_id_str = group_id.to_string();

        // Redis: wipe all round state including last-accepted-share-at + snapshots.
        match self.group_solo.round().reset_full(&group_id_str).await {
            Ok(()) => {
                info!(%group_id, "group-hooks: on_group_dissolved redis reset_full ok");
            }
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    "group-hooks: on_group_dissolved redis reset_full failed (best-effort)"
                );
            }
        }
        // Redis: delete every snapshot of this group.
        // Other wipes spare the per-job keys because they back live jobs;
        // a dissolved group can book no block, so they go too.
        let mut snap_conn = self.group_solo.round().connection_for_snapshot();
        if let Err(err) = bp_group_solo_engine::round::snapshot::delete_everything_for_group(
            &mut snap_conn,
            &group_id_str,
        )
        .await
        {
            warn!(
                %err,
                %group_id,
                "group-hooks: on_group_dissolved delete_all_snapshots failed (best-effort)"
            );
        }

        // PG: delete all block history rows for this group.
        match delete_pplns_group_block_history_for_group(self.db.pool(), group_id).await {
            Ok(n) => {
                info!(%group_id, rows = n, "group-hooks: on_group_dissolved history rows deleted")
            }
            Err(err) => warn!(
                %err,
                %group_id,
                "group-hooks: on_group_dissolved delete history failed (best-effort)"
            ),
        }
    }

    async fn apply_round_reset_config(&self, group: &PplnsGroupRow) {
        // Re-arm this group's round-reset cron so a settings change takes
        // effect without a restart: the old per-group task is replaced by a
        // fresh one, or none if the preset was cleared or the group dissolved.
        self.group_solo.reschedule_group(group);
    }
}

// ─── helpers ─────────────────────────────────────────────────────

fn epoch_ms_to_utc(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_ms_to_utc_round_trips_a_known_timestamp() {
        let dt = epoch_ms_to_utc(1_779_278_400_000);
        assert_eq!(dt.timestamp_millis(), 1_779_278_400_000);
    }

    #[test]
    fn epoch_ms_to_utc_falls_back_to_now_on_invalid_input() {
        // i64::MIN is out of chrono's range; the fallback returns "now"
        // instead of panicking.
        let dt = epoch_ms_to_utc(i64::MIN);
        assert!(dt.timestamp_millis() > 0);
    }
}
