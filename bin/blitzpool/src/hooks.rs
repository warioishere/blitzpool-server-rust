// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production hook impls — Phase 7.3.
//!
//! Wires the four "Noop-by-default" trait surfaces that the bp-api +
//! group-mgmt-engine layers expose against real backends:
//!
//! 1. **`bp_api::EmailVerificationHooks`** — `/api/email/register` +
//!    `/api/email/verify/:token` flow. Sends a verification link
//!    (`/#/email/verify/<token>`) on register and a
//!    binding-change-attempt warning on FCFS-lock rejection.
//! 2. **`bp_group_mgmt_engine::EmailHooks`** — invitation send +
//!    join-decision (approved / rejected) emails fired from the
//!    `InvitationService` + `JoinRequestService` admin paths.
//! 3. **`bp_api::PushHooks`** — `/api/push/{register,fcm/register}`
//!    side-effects. Phase 7.3 keeps both methods best-effort no-ops
//!    (registration doesn't probe the upstream service);
//!    the FCM / Web-Push adapters live in the aggregate so Phase 7.7
//!    can wire them into the `NotificationDispatcher` block-found /
//!    best-diff / device-status event fan-out.
//! 4. **`bp_group_mgmt_engine::GroupServiceHooks`** — last-active
//!    lookup, kick / dissolve cleanup against `GroupRoundStore`'s
//!    Redis keys, min-payout floor lookup.
//!
//! **BlockSubmissionSink** is deliberately out of scope for 7.3 —
//! it requires a small `bp-stratum-v1::ShareAccept` extension
//! (`enonce1: [u8; 4]` + `extranonce2: [u8; 8]` fields) so the
//! adapter can rebuild the witness coinbase for
//! `TdpHandle::submit_solution`. Since the block-submit path doesn't
//! fire until Phase 7.4 binds the Stratum TCP listeners, the
//! ShareAccept extension + the per-SV1/SV2 sink impls naturally
//! co-locate with the Stratum wiring. Tracked in DEFERRED.md under
//! the Phase 7 block.

use std::sync::Arc;

use async_trait::async_trait;
use bp_api::email_hooks::{
    BindingChangeContext as ApiBindingChangeContext, EmailVerificationHooks,
    VerificationContext as ApiVerificationContext,
};
use bp_api::push_hooks::{FcmRegisterContext, PushHooks, UnifiedPushRegisterContext};
use bp_common::{AddressId, Sats};
use bp_config::AppConfig;
use bp_db::Db;
use bp_db::{
    add_pplns_group_balance_pending, delete_pplns_group_balance,
    delete_pplns_group_balances_for_group, delete_pplns_group_block_history_for_group,
    find_address_email, find_group_balance, PplnsGroupRow,
};
use bp_group_mgmt_engine::{
    EmailHooks, GroupServiceHooks, InvitationEmailContext, JoinDecisionEmailContext,
    JoinDecisionOutcome,
};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_group_solo_engine::round::snapshot as group_solo_snapshot;
use bp_notifications::adapter::{
    AdapterError, FcmAdapter, FcmConfig, FcmServiceAccount, SmtpAdapter,
    SmtpConfig as NotifSmtpConfig, VapidConfig, WebPushAdapter,
};
use bp_notifications::template::{
    render_binding_change, render_invitation, render_join_decision, render_verification,
    BindingChangeContext as TplBindingChangeContext, InvitationContext as TplInvitationContext,
    JoinDecision as TplJoinDecision, JoinDecisionContext as TplJoinDecisionContext,
    VerificationContext as TplVerificationContext,
};
use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::boot::FoundationHandles;
use crate::engines::EngineHandles;

/// Aggregate of every production hook impl. Phase 7.4 threads this
/// into the bp-api `AppState` builder + the engine-spawn override
/// paths so the Stratum + HTTP entry points pick up real backends
/// instead of the Noop defaults.
///
/// **Concrete types vs. `Arc<dyn _>`**: the bp-api `AppState` is
/// generic over `H: GroupServiceHooks` + `M: EmailHooks`, so the
/// `group_service` + `invitation_email` fields hold concrete impls
/// (the `SmtpInvitationEmailHooks` wrapper internally holds an
/// `Option<Arc<SmtpAdapter>>` so the type stays the same regardless
/// of whether `[smtp]` was configured). The `email_verification` +
/// `push` fields keep `Arc<dyn _>` because `AppState` already
/// stores those as trait objects.
#[allow(dead_code)]
pub(crate) struct ProductionHooks {
    pub(crate) email_verification: Arc<dyn EmailVerificationHooks>,
    pub(crate) invitation_email: Arc<SmtpInvitationEmailHooks>,
    pub(crate) push: Arc<dyn PushHooks>,
    pub(crate) group_service: Arc<ProductionGroupServiceHooks>,
    /// Concrete FCM adapter, exposed so the Phase 7.5 cron-wiring
    /// (`bin/blitzpool::crons`) can hand it to
    /// [`bp_notifications::cron::spawn_network_difficulty_cron`]
    /// without re-building the adapter. `None` when `[notifications.fcm]`
    /// is not configured — the network-difficulty cron will still spawn
    /// and keep the tracker row fresh, just without push fan-out.
    pub(crate) fcm: Option<Arc<FcmAdapter>>,
    /// Concrete Web-Push adapter, exposed so Phase 7.7's dispatcher
    /// builder can wire it into `NotificationDispatcher::new` without
    /// re-parsing the VAPID config. `None` when `[notifications.web_push]`
    /// isn't configured.
    pub(crate) web_push: Option<Arc<WebPushAdapter>>,
    /// SMTP adapter, exposed so the capacity-monitor cron can send
    /// operator alert emails without re-building the transport.
    /// `None` when `[smtp]` is not configured.
    pub(crate) smtp: Option<Arc<SmtpAdapter>>,
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

/// Build every production hook from `cfg` + the live handles. Each
/// adapter constructor returns an error rather than panicking on
/// bad config so the operator gets a pointed boot-time failure
/// instead of a Stratum-time NPE.
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
    let push: Arc<dyn PushHooks> = Arc::new(MultiChannelPushHooks {
        fcm: fcm.clone(),
        web_push: web_push.clone(),
    });
    let min_payout = cfg
        .pplns
        .as_ref()
        .map(|p| Sats(p.min_payout_sats))
        .unwrap_or(Sats(1000));
    let group_service = Arc::new(ProductionGroupServiceHooks {
        db: foundation.db.clone(),
        group_solo: engines.group_solo.clone(),
        min_payout,
    });

    info!(
        smtp_ready = smtp.is_some(),
        fcm_ready = fcm.is_some(),
        web_push_ready = web_push.is_some(),
        pool_base_url_set = pool_base_url.is_some(),
        min_payout_sats = min_payout.0,
        "production hooks ready"
    );
    Ok(ProductionHooks {
        email_verification,
        invitation_email,
        push,
        group_service,
        fcm,
        web_push,
        smtp,
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
        // VAPID-less Web-Push (plain POST) is still useful for ntfy-
        // compat servers; if the operator hasn't configured the
        // [notifications.web_push] table at all, the adapter just
        // stays absent.
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

/// SMTP-backed email-verification hook. The inner `Option` keeps the
/// struct type-fixed regardless of whether `[smtp]` was configured —
/// `None` ⇒ every method is a quiet no-op: when SMTP isn't enabled the
/// verify-email pathway silently disables itself instead of failing requests.
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

/// SMTP-backed invitation + join-decision email hook. Same Option-
/// keeps-type-fixed pattern as [`SmtpEmailVerificationHooks`] — when
/// SMTP isn't configured the methods are quiet no-ops.
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
    async fn send_invitation(&self, ctx: InvitationEmailContext) {
        let Some(smtp) = self.smtp.as_ref() else {
            return;
        };
        let tpl_ctx = TplInvitationContext {
            address: ctx.address.clone(),
            group_name: ctx.group_name.clone(),
            inviter_address: ctx.inviter_address.clone(),
            invite_url: ctx.accept_url.clone(),
            expires_at: epoch_ms_to_utc(ctx.expires_at_ms),
        };
        let content = render_invitation(&tpl_ctx);
        if let Err(err) = smtp.send_email(&ctx.to_email, &content).await {
            warn!(
                %err,
                to = %ctx.to_email,
                address = %ctx.address,
                group = %ctx.group_name,
                "smtp: send_invitation failed (best-effort)"
            );
        }
    }

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

// ─── bp-api::PushHooks impl ──────────────────────────────────────

/// Holds the FCM + Web-Push adapter handles. Phase 7.3 keeps both
/// hook methods as best-effort no-ops — register doesn't validate the
/// token upstream, on_unified_push_registered doesn't fire a welcome
/// ping. The adapters live in the struct so Phase 7.7 can clone them
/// into the `NotificationDispatcher` block-found / best-diff /
/// device-status fan-out.
#[allow(dead_code)]
pub(crate) struct MultiChannelPushHooks {
    pub(crate) fcm: Option<Arc<FcmAdapter>>,
    pub(crate) web_push: Option<Arc<WebPushAdapter>>,
}

#[async_trait]
impl PushHooks for MultiChannelPushHooks {
    async fn validate_fcm_token(&self, ctx: FcmRegisterContext) {
        // Token validation happens at first-send time, not
        // registration. Log so an operator running with FCM
        // misconfigured sees a per-registration trail.
        if self.fcm.is_none() {
            warn!(
                address = %ctx.address,
                "push.fcm/register received but FCM adapter not configured"
            );
        }
    }

    async fn on_unified_push_registered(&self, _ctx: UnifiedPushRegisterContext) {
        // Registration is a pure DB upsert; no welcome ping. Leave the hook
        // empty so a future deployment can add one without a trait change.
    }
}

// ─── bp-group-mgmt-engine::GroupServiceHooks impl ────────────────

pub(crate) struct ProductionGroupServiceHooks {
    db: Db,
    group_solo: GroupSoloEngine,
    min_payout: Sats,
}

#[async_trait]
impl GroupServiceHooks for ProductionGroupServiceHooks {
    async fn last_active_for_member(&self, group_id: Uuid, address: &AddressId) -> Option<i64> {
        // Redis has the per-share timestamp; PG is only updated on block-found.
        // Try Redis first so active miners who haven't found a block yet don't
        // appear inactive.
        let group_key = group_id.to_string();
        match self
            .group_solo
            .round()
            .read_last_accepted_share_at(&group_key, address.as_str())
            .await
        {
            Ok(Some(ts)) => return Some(ts),
            Ok(None) => {}
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    "group-hooks: last_active_for_member redis failed, falling back to db"
                );
            }
        }
        // PG fallback: persists across Redis resets, accurate after block-found.
        match find_group_balance(self.db.pool(), address, group_id).await {
            Ok(Some(row)) => row.last_accepted_share_at,
            Ok(None) => None,
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    address = %address.as_str(),
                    "group-hooks: last_active_for_member db query failed"
                );
                None
            }
        }
    }

    fn min_payout_sats(&self) -> Sats {
        self.min_payout
    }

    async fn on_member_removed(
        &self,
        group_id: Uuid,
        kicked_address: &AddressId,
        remaining_addresses: &[AddressId],
    ) {
        let group_id_str = group_id.to_string();

        // Redis: zRem + decrement total + hdel by-address/rejected/last-share + del best-share.
        match self
            .group_solo
            .round()
            .forget_member(&group_id_str, kicked_address.as_str())
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

        // Redis: delete the kicked member's per-finder snapshot (TTL fallback otherwise).
        let mut snap_conn = self.group_solo.round().connection_for_snapshot();
        if let Err(err) = group_solo_snapshot::delete_snapshot(
            &mut snap_conn,
            &group_id_str,
            kicked_address.as_str(),
        )
        .await
        {
            warn!(
                %err,
                %group_id,
                address = %kicked_address.as_str(),
                "group-hooks: delete kicked-member snapshot failed (best-effort)"
            );
        }

        // PG: read pending balance before deleting so we can redistribute it.
        let pending_sats = match find_group_balance(self.db.pool(), kicked_address, group_id).await
        {
            Ok(Some(row)) => row.pending_sats.0,
            Ok(None) => 0,
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    address = %kicked_address.as_str(),
                    "group-hooks: find_group_balance failed, redistribution skipped"
                );
                0
            }
        };

        // PG: delete the kicked member's balance row AND redistribute its
        // pending sats to the remaining members — atomically. Without the
        // TX a mid-loop failure would delete the kicked balance but only
        // partially credit the remaining members, silently destroying the
        // uncredited sats (non-custodial: nobody holds them) and drifting
        // the ledger. The TX makes it all-or-nothing: on any error the
        // kicked balance row survives for a retry / dust-sweep, no sats lost.
        let per_member = if pending_sats > 0 && !remaining_addresses.is_empty() {
            pending_sats / remaining_addresses.len() as i64
        } else {
            0
        };
        let now = Utc::now().timestamp_millis();
        let redistribute = async {
            let mut tx = self.db.pool().begin().await?;
            delete_pplns_group_balance(&mut *tx, kicked_address, group_id).await?;
            if per_member > 0 {
                for recipient in remaining_addresses {
                    add_pplns_group_balance_pending(&mut *tx, recipient, group_id, per_member, now)
                        .await?;
                }
            }
            tx.commit().await?;
            Ok::<(), bp_db::DbError>(())
        }
        .await;
        match redistribute {
            Ok(()) => {
                if per_member > 0 {
                    info!(
                        %group_id,
                        address = %kicked_address.as_str(),
                        pending_sats,
                        per_member,
                        recipients = remaining_addresses.len(),
                        "group-hooks: redistributed kicked member pending balance"
                    );
                }
            }
            Err(err) => {
                warn!(
                    %err,
                    %group_id,
                    address = %kicked_address.as_str(),
                    pending_sats,
                    "group-hooks: balance delete+redistribute TX failed; kicked balance \
                     preserved for retry/dust-sweep (no sats lost)"
                );
            }
        }
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
        // Redis: delete all per-finder snapshots for this group.
        let mut snap_conn = self.group_solo.round().connection_for_snapshot();
        if let Err(err) = bp_group_solo_engine::round::snapshot::delete_all_for_group(
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

        // PG: delete all balance rows for this group.
        match delete_pplns_group_balances_for_group(self.db.pool(), group_id).await {
            Ok(n) => {
                info!(%group_id, rows = n, "group-hooks: on_group_dissolved balance rows deleted")
            }
            Err(err) => warn!(
                %err,
                %group_id,
                "group-hooks: on_group_dissolved delete balances failed (best-effort)"
            ),
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
        // Re-arm this group's round-reset cron at runtime so a settings change
        // (preset / interval / timezone) takes effect immediately, without a
        // pool restart. The engine tears down the old per-group task and spawns
        // a fresh one — or none, if the group cleared its preset or dissolved.
        self.group_solo.reschedule_group(group);
    }
}

// ─── helpers ─────────────────────────────────────────────────────

fn epoch_ms_to_utc(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(Utc::now)
}

// pull AddressEmailRow via find_address_email — silence "unused
// import" because Phase 7.4 will use this for the verification
// resend path. Kept here so the compile-time wiring confirms the
// helper exists.
#[allow(dead_code)]
async fn _ensure_find_address_email_resolves(db: &Db, addr: &AddressId) {
    let _ = find_address_email(db.pool(), addr).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_ms_to_utc_round_trips_a_known_timestamp() {
        // 2026-05-16T12:00:00Z = 1_779_278_400_000 ms (epoch ms).
        let dt = epoch_ms_to_utc(1_779_278_400_000);
        assert_eq!(dt.timestamp_millis(), 1_779_278_400_000);
    }

    #[test]
    fn epoch_ms_to_utc_falls_back_to_now_on_invalid_input() {
        // i64::MIN is out of the valid range for chrono::DateTime<Utc>;
        // the fallback path should return a finite "now" instead of
        // panicking. We can't assert the exact value so we just
        // confirm it doesn't wrap to a sentinel.
        let dt = epoch_ms_to_utc(i64::MIN);
        assert!(dt.timestamp_millis() > 0);
    }

    #[test]
    fn multi_channel_push_hooks_can_be_constructed_without_adapters() {
        let hooks = MultiChannelPushHooks {
            fcm: None,
            web_push: None,
        };
        // Compile-check only — we can't drive PushHooks methods from a
        // sync test without a runtime, and the methods are no-ops in
        // the "no adapters configured" path anyway.
        let _ = hooks.fcm.is_some();
        let _ = hooks.web_push.is_some();
    }
}
