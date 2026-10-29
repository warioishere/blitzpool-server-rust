// SPDX-License-Identifier: AGPL-3.0-or-later

//! Address-access template, sent by the API to an address's verified email
//! when its holder asks for a link to set the address's password.

use chrono::{DateTime, Utc};

use super::content::EmailContent;
use super::helpers::{
    button_html, escape_attr, escape_html, format_utc_string, shell_html, COLOR_BG, COLOR_MUTED,
    COLOR_PRIMARY, COLOR_TEXT,
};

/// Inputs for [`render_address_access`]. Recipient (`to:`) is supplied by
/// the adapter when sending, not by the template.
#[derive(Debug, Clone)]
pub struct AddressAccessContext {
    /// Mining address the link is for (displayed verbatim, escaped at render).
    pub address: String,
    /// Link carrying the address token.
    pub access_url: String,
    /// When the link expires.
    pub expires_at: DateTime<Utc>,
}

const SUBJECT: &str = "Set the password for your address \u{2014} Blitz Pool";

/// Render the address-access email (subject + HTML + text).
pub fn render_address_access(ctx: &AddressAccessContext) -> EmailContent {
    EmailContent {
        subject: SUBJECT.to_string(),
        html: render_html(ctx),
        text: render_text(ctx),
    }
}

fn render_html(ctx: &AddressAccessContext) -> String {
    let expires = format_utc_string(&ctx.expires_at);
    let body = format!(
        "\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">Set the password for your address</h1>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
This link sets the password for your mining address on Blitz Pool:\n\
</p>\n\
<p style=\"margin:0 0 24px;padding:12px 16px;background:{bg};border-radius:6px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};word-break:break-all;\">\n  \
{address}\n\
</p>\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 24px;\">\n  \
<tr><td>{button}</td></tr>\n\
</table>\n\
<p style=\"margin:0 0 8px;font-size:12px;color:{muted};\">\n  \
Or paste this link into your browser:\n\
</p>\n\
<p style=\"margin:0 0 24px;font-size:12px;color:{muted};word-break:break-all;\">\n  \
<a href=\"{url_attr}\" style=\"color:{primary};text-decoration:underline;\">{url_text}</a>\n\
</p>\n\
<p style=\"margin:0 0 8px;font-size:12px;color:{muted};\">\n  \
Link expires {expires}.\n\
</p>\n\
<p style=\"margin:0;font-size:12px;color:{muted};\">\n  \
If you didn't request this, ignore the email.\n\
</p>\n",
        text = COLOR_TEXT,
        bg = COLOR_BG,
        primary = COLOR_PRIMARY,
        muted = COLOR_MUTED,
        address = escape_html(&ctx.address),
        button = button_html(&ctx.access_url, "Set password", true),
        url_attr = escape_attr(&ctx.access_url),
        url_text = escape_html(&ctx.access_url),
        expires = escape_html(&expires),
    );
    shell_html("Set the password for your address", &body)
}

fn render_text(ctx: &AddressAccessContext) -> String {
    [
        "Set the password for your address on Blitz Pool",
        "",
        &format!("Address: {}", ctx.address),
        "",
        &format!("Set it here: {}", ctx.access_url),
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

    fn ctx() -> AddressAccessContext {
        AddressAccessContext {
            address: "bc1qexampleaddress".to_string(),
            access_url: "https://blitzpool.example/#/address-access/bc1qexampleaddress/abc.def"
                .to_string(),
            expires_at: Utc.with_ymd_and_hms(2026, 5, 16, 12, 34, 56).unwrap(),
        }
    }

    #[test]
    fn html_carries_address_button_link_and_expiry() {
        let c = render_address_access(&ctx());
        assert_eq!(
            c.subject,
            "Set the password for your address \u{2014} Blitz Pool"
        );
        assert!(c.html.contains("bc1qexampleaddress"));
        assert!(c.html.contains(">Set password</a>"));
        assert!(c.html.contains(
            "href=\"https://blitzpool.example/#/address-access/bc1qexampleaddress/abc.def\""
        ));
        assert!(c
            .html
            .contains("Link expires Sat, 16 May 2026 12:34:56 GMT."));
    }

    #[test]
    fn text_names_address_link_and_expiry() {
        assert_eq!(
            render_address_access(&ctx()).text,
            "Set the password for your address on Blitz Pool\n\
\n\
Address: bc1qexampleaddress\n\
\n\
Set it here: https://blitzpool.example/#/address-access/bc1qexampleaddress/abc.def\n\
\n\
Link expires Sat, 16 May 2026 12:34:56 GMT.\n\
\n\
If you didn't request this, ignore the email."
        );
    }

    #[test]
    fn html_address_is_escaped() {
        let mut c_ctx = ctx();
        c_ctx.address = "<script>x</script>".to_string();
        let c = render_address_access(&c_ctx);
        assert!(!c.html.contains("<script>x"));
        assert!(c.html.contains("&lt;script&gt;x&lt;/script&gt;"));
    }
}
