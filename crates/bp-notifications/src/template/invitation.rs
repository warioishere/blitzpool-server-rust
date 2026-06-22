// SPDX-License-Identifier: AGPL-3.0-or-later

//! Payout-group invitation template — sent by
//! `PplnsGroupInvitationService.createInvitation()`.

use chrono::{DateTime, Utc};

use super::content::EmailContent;
use super::helpers::{
    button_html, escape_attr, escape_html, format_utc_string, sanitize_header, shell_html,
    COLOR_BG, COLOR_MUTED, COLOR_PRIMARY, COLOR_TEXT,
};

/// Inputs for [`render_invitation`]. Recipient (`to:`) is supplied by
/// the adapter when sending, not by the template.
#[derive(Debug, Clone)]
pub struct InvitationContext {
    /// The mining address that the invitation is for.
    pub address: String,
    /// Display name of the group (subject + body, sanitized for the
    /// header and HTML-escaped for the body).
    pub group_name: String,
    /// Address of the group admin who sent the invitation.
    pub inviter_address: String,
    /// UI page where the recipient reviews and accepts / declines.
    pub invite_url: String,
    /// When the invitation link expires.
    pub expires_at: DateTime<Utc>,
}

/// Render the invitation email (subject + HTML + text).
pub fn render_invitation(ctx: &InvitationContext) -> EmailContent {
    EmailContent {
        subject: format!(
            "Invitation to join {} \u{2014} Blitz Pool",
            sanitize_header(&ctx.group_name)
        ),
        html: render_html(ctx),
        text: render_text(ctx),
    }
}

fn render_html(ctx: &InvitationContext) -> String {
    let expires = format_utc_string(&ctx.expires_at);
    let body = format!(
        "\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">Group invitation</h1>\n\
<p style=\"margin:0 0 24px;font-size:14px;line-height:1.6;color:{text};\">\n  \
You've been invited to join the payout group <strong style=\"color:{primary};\">{group_name}</strong>.\n\
</p>\n\
<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 24px;background:{bg};border-radius:6px;\">\n  \
<tr><td style=\"padding:16px;\">\n    \
<p style=\"margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:{muted};\">Your address</p>\n    \
<p style=\"margin:0 0 16px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};word-break:break-all;\">\n      \
{address}\n    \
</p>\n    \
<p style=\"margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:{muted};\">Invited by</p>\n    \
<p style=\"margin:0;font-family:'Roboto Mono',monospace;font-size:13px;color:{text};word-break:break-all;\">\n      \
{inviter}\n    \
</p>\n  \
</td></tr>\n\
</table>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Open the invitation page to review it and accept or decline. When you accept, your mining address joins this group and future blocks you find will be paid out via the group's PROP-style coinbase split.\n\
</p>\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 24px;\">\n  \
<tr><td>{button}</td></tr>\n\
</table>\n\
<p style=\"margin:0 0 8px;font-size:12px;color:{muted};\">\n  \
Or paste this link into your browser:\n\
</p>\n\
<p style=\"margin:0 0 24px;font-size:12px;color:{muted};word-break:break-all;\">\n  \
<a href=\"{invite_attr}\" style=\"color:{primary};text-decoration:underline;\">{invite_text}</a>\n\
</p>\n\
<p style=\"margin:0;font-size:12px;color:{muted};\">\n  \
Invitation expires {expires}. If you don't recognise the inviter, decline.\n\
</p>\n",
        text = COLOR_TEXT,
        primary = COLOR_PRIMARY,
        bg = COLOR_BG,
        muted = COLOR_MUTED,
        group_name = escape_html(&ctx.group_name),
        address = escape_html(&ctx.address),
        inviter = escape_html(&ctx.inviter_address),
        button = button_html(&ctx.invite_url, "Open invitation", true),
        invite_attr = escape_attr(&ctx.invite_url),
        invite_text = escape_html(&ctx.invite_url),
        expires = escape_html(&expires),
    );
    shell_html(
        &format!("Invitation to join {}", sanitize_header(&ctx.group_name)),
        &body,
    )
}

fn render_text(ctx: &InvitationContext) -> String {
    [
        &format!(
            "You've been invited to join the payout group \"{}\" on Blitz Pool.",
            sanitize_header(&ctx.group_name)
        ),
        "",
        &format!("Your address: {}", ctx.address),
        &format!("Invited by:   {}", ctx.inviter_address),
        "",
        &format!("Open the invitation: {}", ctx.invite_url),
        "",
        &format!("Invitation expires {}.", format_utc_string(&ctx.expires_at)),
        "If you don't recognise the inviter, decline.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ctx() -> InvitationContext {
        InvitationContext {
            address: "bc1qrecipientaddr".to_string(),
            group_name: "Mining Buddies".to_string(),
            inviter_address: "bc1qinviteradminaddr".to_string(),
            invite_url: "https://blitzpool.example/#/invite/tok123".to_string(),
            expires_at: Utc.with_ymd_and_hms(2026, 5, 23, 9, 0, 0).unwrap(),
        }
    }

    #[test]
    fn subject_includes_sanitized_group_name_and_brand() {
        let c = render_invitation(&ctx());
        assert_eq!(
            c.subject,
            "Invitation to join Mining Buddies \u{2014} Blitz Pool"
        );
    }

    #[test]
    fn subject_strips_header_injection_attempts() {
        let mut c_ctx = ctx();
        c_ctx.group_name = "evil\r\nBcc: a@b.c".to_string();
        let s = render_invitation(&c_ctx).subject;
        assert!(!s.contains('\r'));
        assert!(!s.contains('\n'));
        assert!(s.contains("evil  Bcc: a@b.c"));
    }

    #[test]
    fn html_features_group_name_in_primary_color_strong() {
        let c = render_invitation(&ctx());
        assert!(c.html.contains(&format!(
            "<strong style=\"color:{COLOR_PRIMARY};\">Mining Buddies</strong>"
        )));
    }

    #[test]
    fn html_button_label_is_open_invitation() {
        let c = render_invitation(&ctx());
        assert!(c.html.contains(">Open invitation</a>"));
    }

    #[test]
    fn html_includes_address_and_inviter() {
        let c = render_invitation(&ctx());
        assert!(c.html.contains("bc1qrecipientaddr"));
        assert!(c.html.contains("bc1qinviteradminaddr"));
    }

    #[test]
    fn html_renders_expiry_and_warning_line() {
        let c = render_invitation(&ctx());
        assert!(c.html.contains(
            "Invitation expires Sat, 23 May 2026 09:00:00 GMT. If you don't recognise the inviter, decline."
        ));
    }

    #[test]
    fn text_quote_group_name_uses_sanitized_form() {
        let c = render_invitation(&ctx());
        assert!(c.text.starts_with(
            "You've been invited to join the payout group \"Mining Buddies\" on Blitz Pool.\n"
        ));
        assert!(c.text.contains("Your address: bc1qrecipientaddr"));
        assert!(c.text.contains("Invited by:   bc1qinviteradminaddr"));
        assert!(c
            .text
            .contains("Open the invitation: https://blitzpool.example/#/invite/tok123"));
        assert!(c
            .text
            .contains("Invitation expires Sat, 23 May 2026 09:00:00 GMT."));
        assert!(c
            .text
            .ends_with("If you don't recognise the inviter, decline."));
    }

    #[test]
    fn html_group_name_is_escaped_in_body() {
        let mut c_ctx = ctx();
        c_ctx.group_name = "<b>boom</b>".to_string();
        let c = render_invitation(&c_ctx);
        assert!(!c.html.contains("<b>boom</b>"));
        assert!(c.html.contains("&lt;b&gt;boom&lt;/b&gt;"));
    }
}
