// SPDX-License-Identifier: AGPL-3.0-or-later

//! Email-binding confirmation template — sent by `AddressEmailService`
//! when a new address↔email registration starts.

use chrono::{DateTime, Utc};

use super::content::EmailContent;
use super::helpers::{
    button_html, escape_attr, escape_html, format_utc_string, shell_html, COLOR_BG, COLOR_MUTED,
    COLOR_PRIMARY, COLOR_TEXT,
};

/// Inputs for [`render_verification`]. Recipient (`to:`) is supplied by
/// the adapter when sending, not by the template.
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// Mining address being bound (displayed verbatim, escaped at render).
    pub address: String,
    /// Confirmation link with the verification token.
    pub verify_url: String,
    /// When the verification link expires.
    pub expires_at: DateTime<Utc>,
}

const SUBJECT: &str = "Confirm your email address \u{2014} Blitz Pool";

/// Render the verification email (subject + HTML + text).
pub fn render_verification(ctx: &VerificationContext) -> EmailContent {
    EmailContent {
        subject: SUBJECT.to_string(),
        html: render_html(ctx),
        text: render_text(ctx),
    }
}

fn render_html(ctx: &VerificationContext) -> String {
    let expires = format_utc_string(&ctx.expires_at);
    let body = format!(
        "\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">Confirm your email address</h1>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
This email is being bound to mining address:\n\
</p>\n\
<p style=\"margin:0 0 24px;padding:12px 16px;background:{bg};border-radius:6px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};word-break:break-all;\">\n  \
{address}\n\
</p>\n\
<p style=\"margin:0 0 24px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Click the button below to confirm. Once confirmed, payout-group admins will be able to invite this address into their group.\n\
</p>\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 24px;\">\n  \
<tr><td>{button}</td></tr>\n\
</table>\n\
<p style=\"margin:0 0 8px;font-size:12px;color:{muted};\">\n  \
Or paste this link into your browser:\n\
</p>\n\
<p style=\"margin:0 0 24px;font-size:12px;color:{muted};word-break:break-all;\">\n  \
<a href=\"{verify_attr}\" style=\"color:{primary};text-decoration:underline;\">{verify_text}</a>\n\
</p>\n\
<p style=\"margin:0;font-size:12px;color:{muted};\">\n  \
Link expires {expires}.\n\
</p>\n",
        text = COLOR_TEXT,
        bg = COLOR_BG,
        primary = COLOR_PRIMARY,
        muted = COLOR_MUTED,
        address = escape_html(&ctx.address),
        button = button_html(&ctx.verify_url, "Confirm email", true),
        verify_attr = escape_attr(&ctx.verify_url),
        verify_text = escape_html(&ctx.verify_url),
        expires = escape_html(&expires),
    );
    shell_html("Confirm your email address", &body)
}

fn render_text(ctx: &VerificationContext) -> String {
    [
        "Confirm your email for Blitz Pool",
        "",
        &format!("Address: {}", ctx.address),
        "",
        &format!("Click to confirm: {}", ctx.verify_url),
        "",
        &format!("Link expires {}.", format_utc_string(&ctx.expires_at)),
        "",
        "If you didn't request this, ignore the email.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ctx() -> VerificationContext {
        VerificationContext {
            address: "bc1qexampleaddress".to_string(),
            verify_url: "https://blitzpool.example/verify?token=abc&id=1".to_string(),
            expires_at: Utc.with_ymd_and_hms(2026, 5, 16, 12, 34, 56).unwrap(),
        }
    }

    #[test]
    fn subject_is_static() {
        assert_eq!(
            render_verification(&ctx()).subject,
            "Confirm your email address \u{2014} Blitz Pool"
        );
    }

    #[test]
    fn html_includes_shell_brand_and_button() {
        let c = render_verification(&ctx());
        assert!(c.html.contains("\u{26a1} Blitz Pool"));
        assert!(c.html.contains("Confirm your email address</h1>"));
        assert!(c.html.contains("bc1qexampleaddress"));
        assert!(c.html.contains(">Confirm email</a>"));
    }

    #[test]
    fn html_escapes_url_in_attr_and_text_contexts() {
        let c = render_verification(&ctx());
        // attr context: & → &amp;
        assert!(c
            .html
            .contains("href=\"https://blitzpool.example/verify?token=abc&amp;id=1\""));
        // visible link text — &amp; too (escape_html escapes &)
        assert!(c
            .html
            .contains(">https://blitzpool.example/verify?token=abc&amp;id=1</a>"));
    }

    #[test]
    fn html_renders_expiry_in_utc_string_form() {
        let c = render_verification(&ctx());
        assert!(c
            .html
            .contains("Link expires Sat, 16 May 2026 12:34:56 GMT."));
    }

    #[test]
    fn text_is_seven_lines_plus_ignore_footer() {
        let c = render_verification(&ctx());
        assert_eq!(
            c.text,
            "Confirm your email for Blitz Pool\n\
\n\
Address: bc1qexampleaddress\n\
\n\
Click to confirm: https://blitzpool.example/verify?token=abc&id=1\n\
\n\
Link expires Sat, 16 May 2026 12:34:56 GMT.\n\
\n\
If you didn't request this, ignore the email."
        );
    }

    #[test]
    fn html_address_is_escaped() {
        let mut c_ctx = ctx();
        c_ctx.address = "<script>alert('x')</script>".to_string();
        let c = render_verification(&c_ctx);
        // Must NOT contain raw <script>
        assert!(!c.html.contains("<script>alert"));
        // Escaped form present.
        assert!(c
            .html
            .contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
    }
}
