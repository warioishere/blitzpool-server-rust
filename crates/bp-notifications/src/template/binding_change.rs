// SPDX-License-Identifier: AGPL-3.0-or-later

//! K1-lock attempted-takeover notice — sent by `AddressEmailService`
//! when an existing address↔email binding refuses a re-registration.

use super::content::EmailContent;
use super::helpers::{
    escape_html, shell_html, COLOR_BG, COLOR_MUTED, COLOR_PRIMARY, COLOR_PRIMARY_TEXT, COLOR_TEXT,
};

/// Inputs for [`render_binding_change`]. Recipient (`to:`) is supplied
/// by the adapter — that recipient is the legitimate, currently-bound
/// email; the attempted email is shown pre-masked.
#[derive(Debug, Clone)]
pub struct BindingChangeContext {
    /// Mining address whose binding someone tried to overwrite.
    pub address: String,
    /// Pre-masked form of the email someone just tried to bind
    /// (caller is responsible for the masking, e.g. `a***@example.com`).
    pub attempted_email_masked: String,
}

const SUBJECT: &str = "Attempted email-binding change on your mining address \u{2014} Blitz Pool";

/// Render the binding-change-attempt email (subject + HTML + text).
pub fn render_binding_change(ctx: &BindingChangeContext) -> EmailContent {
    EmailContent {
        subject: SUBJECT.to_string(),
        html: render_html(ctx),
        text: render_text(ctx),
    }
}

fn render_html(ctx: &BindingChangeContext) -> String {
    let body = format!(
        "\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 20px;\">\n  \
<tr><td style=\"background:#FFB74D;color:{primary_text};padding:4px 12px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.1em;\">\n    \
NOTICE\n  \
</td></tr>\n\
</table>\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">Attempted email-binding change</h1>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Someone just tried to register a different email against your mining address:\n\
</p>\n\
<p style=\"margin:0 0 24px;padding:12px 16px;background:{bg};border-radius:6px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};word-break:break-all;\">\n  \
{address}\n\
</p>\n\
<p style=\"margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:{muted};\">Attempted new email</p>\n\
<p style=\"margin:0 0 24px;font-family:'Roboto Mono',monospace;font-size:14px;color:{text};\">\n  \
{attempted}\n\
</p>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
The attempt was <strong style=\"color:{primary};\">refused</strong>. Your existing binding is still active and group invitations continue to come to this email address.\n\
</p>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
No action is required if this was you (e.g. you typed your address by mistake on a friend's device). If you don't recognise this, your address may be on a public block-finder list \u{2014} there is no exposure beyond this notification.\n\
</p>\n\
<p style=\"margin:0;font-size:12px;color:{muted};\">\n  \
This is an automated security notification. You will not receive a separate email per attempt \u{2014} only the first within a short window.\n\
</p>\n",
        text = COLOR_TEXT,
        primary_text = COLOR_PRIMARY_TEXT,
        bg = COLOR_BG,
        primary = COLOR_PRIMARY,
        muted = COLOR_MUTED,
        address = escape_html(&ctx.address),
        attempted = escape_html(&ctx.attempted_email_masked),
    );
    shell_html("Attempted email-binding change", &body)
}

fn render_text(ctx: &BindingChangeContext) -> String {
    [
        "Attempted email-binding change on Blitz Pool",
        "",
        "Someone tried to register a different email against your mining address:",
        &format!("  {}", ctx.address),
        "",
        &format!("Attempted new email: {}", ctx.attempted_email_masked),
        "",
        "The attempt was REFUSED. Your existing binding is still active and group invitations continue to come to this email address.",
        "",
        "No action is required. If you don't recognise this, your address is likely on a public block-finder list — there is no exposure beyond this notification.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> BindingChangeContext {
        BindingChangeContext {
            address: "bc1qexistingowner".to_string(),
            attempted_email_masked: "a***@example.com".to_string(),
        }
    }

    #[test]
    fn subject_is_static() {
        assert_eq!(
            render_binding_change(&ctx()).subject,
            "Attempted email-binding change on your mining address \u{2014} Blitz Pool"
        );
    }

    #[test]
    fn html_has_notice_badge_address_and_masked_email() {
        let c = render_binding_change(&ctx());
        assert!(c.html.contains("NOTICE"));
        assert!(c.html.contains("background:#FFB74D"));
        assert!(c.html.contains("Attempted email-binding change</h1>"));
        assert!(c.html.contains("bc1qexistingowner"));
        assert!(c.html.contains("a***@example.com"));
        assert!(c
            .html
            .contains("<strong style=\"color:#9FA8DA;\">refused</strong>"));
    }

    #[test]
    fn html_explains_no_separate_email_per_attempt() {
        let c = render_binding_change(&ctx());
        assert!(c.html.contains("only the first within a short window"));
    }

    #[test]
    fn text_layout_includes_masked_email() {
        let c = render_binding_change(&ctx());
        assert!(c
            .text
            .starts_with("Attempted email-binding change on Blitz Pool\n"));
        assert!(c.text.contains("  bc1qexistingowner"));
        assert!(c.text.contains("Attempted new email: a***@example.com"));
        assert!(c.text.contains("REFUSED"));
        assert!(c
            .text
            .ends_with("there is no exposure beyond this notification."));
    }

    #[test]
    fn html_escapes_address_and_masked_email() {
        let mut c_ctx = ctx();
        c_ctx.address = "<bad>".to_string();
        c_ctx.attempted_email_masked = "x\"y&z".to_string();
        let c = render_binding_change(&c_ctx);
        assert!(c.html.contains("&lt;bad&gt;"));
        assert!(c.html.contains("x&quot;y&amp;z"));
    }
}
