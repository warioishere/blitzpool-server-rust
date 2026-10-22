// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mail to a Team's admin when an address asks to join the Team — sent
//! only when the admin follows the Team on no push channel.

use super::content::EmailContent;
use super::helpers::{
    button_html, escape_attr, escape_html, sanitize_header, shell_html, COLOR_BG, COLOR_MUTED,
    COLOR_PRIMARY, COLOR_TEXT,
};

/// Inputs for [`render_join_request_admin`]. Recipient (`to:`) is supplied
/// by the adapter when sending, not by the template.
#[derive(Debug, Clone)]
pub struct JoinRequestAdminContext {
    /// The address asking to join.
    pub requester_address: String,
    pub group_name: String,
    /// The Team's admin panel, where the request is approved or rejected.
    pub admin_url: String,
}

/// Render the admin's join-request email (subject + HTML + text).
pub fn render_join_request_admin(ctx: &JoinRequestAdminContext) -> EmailContent {
    EmailContent {
        subject: format!(
            "New join request for {} \u{2014} Blitz Pool",
            sanitize_header(&ctx.group_name)
        ),
        html: render_html(ctx),
        text: render_text(ctx),
    }
}

fn render_html(ctx: &JoinRequestAdminContext) -> String {
    let headline = "New join request";
    let body = format!(
        "\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">{headline}</h1>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
This address asks to join your Team <strong style=\"color:{primary};\">{group_name}</strong>:\n\
</p>\n\
<p style=\"margin:0 0 24px;padding:12px 16px;background:{bg};border-radius:6px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};word-break:break-all;\">\n  \
{address}\n\
</p>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Approve or reject it in the Team's admin panel.\n\
</p>\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 24px;\">\n  \
<tr><td>{button}</td></tr>\n\
</table>\n\
<p style=\"margin:0;font-size:12px;color:{muted};\">\n  \
Or paste this link: <a href=\"{href_attr}\" style=\"color:{primary};\">{href_text}</a>\n\
</p>\n",
        text = COLOR_TEXT,
        primary = COLOR_PRIMARY,
        bg = COLOR_BG,
        muted = COLOR_MUTED,
        headline = escape_html(headline),
        group_name = escape_html(&ctx.group_name),
        address = escape_html(&ctx.requester_address),
        button = button_html(&ctx.admin_url, "Open admin panel", true),
        href_attr = escape_attr(&ctx.admin_url),
        href_text = escape_html(&ctx.admin_url),
    );
    shell_html(headline, &body)
}

fn render_text(ctx: &JoinRequestAdminContext) -> String {
    [
        &format!(
            "This address asks to join your Team \"{}\":",
            sanitize_header(&ctx.group_name)
        ),
        "",
        &ctx.requester_address,
        "",
        &format!("Approve or reject it in the admin panel: {}", ctx.admin_url),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> JoinRequestAdminContext {
        JoinRequestAdminContext {
            requester_address: "bc1qjoiner".to_string(),
            group_name: "PoolPals".to_string(),
            admin_url: "https://blitzpool.example/#/app/bc1qadmin/payout-group/admin".to_string(),
        }
    }

    #[test]
    fn subject_names_the_team() {
        assert_eq!(
            render_join_request_admin(&ctx()).subject,
            "New join request for PoolPals \u{2014} Blitz Pool"
        );
    }

    #[test]
    fn html_names_requester_team_and_links_the_admin_panel() {
        let c = render_join_request_admin(&ctx());
        assert!(c.html.contains("bc1qjoiner"));
        assert!(c.html.contains("PoolPals"));
        assert!(c.html.contains(">Open admin panel</a>"));
        assert!(c
            .html
            .contains("https://blitzpool.example/#/app/bc1qadmin/payout-group/admin"));
    }

    #[test]
    fn text_layout() {
        assert_eq!(
            render_join_request_admin(&ctx()).text,
            "This address asks to join your Team \"PoolPals\":\n\
\n\
bc1qjoiner\n\
\n\
Approve or reject it in the admin panel: https://blitzpool.example/#/app/bc1qadmin/payout-group/admin"
        );
    }

    #[test]
    fn group_name_html_escaped_in_body_but_sanitized_in_subject() {
        let mut c_ctx = ctx();
        c_ctx.group_name = "evil<\r\n>group".to_string();
        let c = render_join_request_admin(&c_ctx);
        assert_eq!(
            c.subject,
            "New join request for evil<  >group \u{2014} Blitz Pool"
        );
        assert!(c.html.contains("evil&lt;\r\n&gt;group"));
        assert!(!c.html.contains("evil<\r\n>group"));
    }
}
