// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public join-request approval / rejection template — sent by
//! `PplnsGroupJoinRequestService.{approveRequest,rejectRequest}`.

use super::content::EmailContent;
use super::helpers::{
    button_html, escape_attr, escape_html, sanitize_header, shell_html, COLOR_BG, COLOR_MUTED,
    COLOR_PRIMARY, COLOR_TEXT,
};

/// Inputs for [`render_join_decision`]. Recipient (`to:`) is supplied
/// by the adapter when sending, not by the template.
#[derive(Debug, Clone)]
pub struct JoinDecisionContext {
    pub address: String,
    pub group_name: String,
    /// Group dashboard URL (approved) or public-groups directory URL
    /// (rejected) — caller decides which.
    pub group_url: String,
}

/// Which decision branch to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinDecision {
    Approved,
    Rejected,
}

/// Render the decision email (subject + HTML + text).
pub fn render_join_decision(ctx: &JoinDecisionContext, decision: JoinDecision) -> EmailContent {
    EmailContent {
        subject: subject(ctx, decision),
        html: render_html(ctx, decision),
        text: render_text(ctx, decision),
    }
}

fn subject(ctx: &JoinDecisionContext, decision: JoinDecision) -> String {
    let group = sanitize_header(&ctx.group_name);
    match decision {
        JoinDecision::Approved => format!("Welcome to {group} \u{2014} Blitz Pool"),
        JoinDecision::Rejected => {
            format!("Join request to {group} declined \u{2014} Blitz Pool")
        }
    }
}

fn render_html(ctx: &JoinDecisionContext, decision: JoinDecision) -> String {
    let is_approved = matches!(decision, JoinDecision::Approved);
    let headline = if is_approved {
        "Welcome \u{2014} request approved"
    } else {
        "Request declined"
    };
    let decision_word = if is_approved { "approved" } else { "declined" };

    let tail = if is_approved {
        format!(
            "\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Your address is now a member. Future blocks will be paid out via the group's PROP-style coinbase split.\n\
</p>\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 24px;\">\n  \
<tr><td>{button}</td></tr>\n\
</table>\n\
<p style=\"margin:0;font-size:12px;color:{muted};\">\n  \
Or paste this link: <a href=\"{href_attr}\" style=\"color:{primary};\">{href_text}</a>\n\
</p>\n",
            text = COLOR_TEXT,
            muted = COLOR_MUTED,
            primary = COLOR_PRIMARY,
            button = button_html(&ctx.group_url, "Open group dashboard", true),
            href_attr = escape_attr(&ctx.group_url),
            href_text = escape_html(&ctx.group_url),
        )
    } else {
        format!(
            "\n\
<p style=\"margin:0;font-size:14px;line-height:1.6;color:{text};\">\n  \
No further action is needed. You can request to join other public groups any time.\n\
</p>\n",
            text = COLOR_TEXT,
        )
    };

    let body = format!(
        "\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">{headline}</h1>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Your join request to <strong style=\"color:{primary};\">{group_name}</strong> has been\n  \
<strong>{decision_word}</strong> by the group admin.\n\
</p>\n\
<p style=\"margin:0 0 24px;padding:12px 16px;background:{bg};border-radius:6px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};word-break:break-all;\">\n  \
{address}\n\
</p>\n\
{tail}",
        text = COLOR_TEXT,
        primary = COLOR_PRIMARY,
        bg = COLOR_BG,
        headline = escape_html(headline),
        group_name = escape_html(&ctx.group_name),
        decision_word = decision_word,
        address = escape_html(&ctx.address),
        tail = tail,
    );
    shell_html(headline, &body)
}

fn render_text(ctx: &JoinDecisionContext, decision: JoinDecision) -> String {
    let group = sanitize_header(&ctx.group_name);
    match decision {
        JoinDecision::Approved => [
            &format!("Your join request to \"{group}\" was approved."),
            "",
            &format!("Address: {}", ctx.address),
            "",
            &format!("Open group dashboard: {}", ctx.group_url),
        ]
        .join("\n"),
        JoinDecision::Rejected => [
            &format!("Your join request to \"{group}\" was declined by the admin."),
            "",
            &format!("Address: {}", ctx.address),
            "",
            "No further action is needed. You can request to join other public groups any time.",
        ]
        .join("\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> JoinDecisionContext {
        JoinDecisionContext {
            address: "bc1qjoiner".to_string(),
            group_name: "PoolPals".to_string(),
            group_url: "https://blitzpool.example/#/app/bc1qjoiner/payout-group".to_string(),
        }
    }

    #[test]
    fn approved_subject() {
        assert_eq!(
            render_join_decision(&ctx(), JoinDecision::Approved).subject,
            "Welcome to PoolPals \u{2014} Blitz Pool"
        );
    }

    #[test]
    fn rejected_subject() {
        assert_eq!(
            render_join_decision(&ctx(), JoinDecision::Rejected).subject,
            "Join request to PoolPals declined \u{2014} Blitz Pool"
        );
    }

    #[test]
    fn approved_html_has_button_and_dashboard_url() {
        let c = render_join_decision(&ctx(), JoinDecision::Approved);
        assert!(c.html.contains("Welcome \u{2014} request approved"));
        assert!(c.html.contains(">Open group dashboard</a>"));
        assert!(c.html.contains("<strong>approved</strong>"));
        assert!(c.html.contains("bc1qjoiner"));
        assert!(c.html.contains("PoolPals"));
    }

    #[test]
    fn rejected_html_has_no_button_and_explains_no_action() {
        let c = render_join_decision(&ctx(), JoinDecision::Rejected);
        assert!(c.html.contains("Request declined</h1>"));
        assert!(c.html.contains("<strong>declined</strong>"));
        assert!(!c.html.contains("Open group dashboard"));
        assert!(c.html.contains(
            "No further action is needed. You can request to join other public groups any time."
        ));
    }

    #[test]
    fn approved_text_layout() {
        let c = render_join_decision(&ctx(), JoinDecision::Approved);
        assert_eq!(
            c.text,
            "Your join request to \"PoolPals\" was approved.\n\
\n\
Address: bc1qjoiner\n\
\n\
Open group dashboard: https://blitzpool.example/#/app/bc1qjoiner/payout-group"
        );
    }

    #[test]
    fn rejected_text_layout() {
        let c = render_join_decision(&ctx(), JoinDecision::Rejected);
        assert_eq!(
            c.text,
            "Your join request to \"PoolPals\" was declined by the admin.\n\
\n\
Address: bc1qjoiner\n\
\n\
No further action is needed. You can request to join other public groups any time."
        );
    }

    #[test]
    fn group_name_html_escaped_in_body_but_sanitized_in_subject() {
        let mut c_ctx = ctx();
        c_ctx.group_name = "evil<\r\n>group".to_string();
        let c = render_join_decision(&c_ctx, JoinDecision::Approved);
        // Subject: \r\n stripped (becomes space), `<` preserved (no HTML escape on subject).
        assert_eq!(c.subject, "Welcome to evil<  >group \u{2014} Blitz Pool");
        // Body HTML: escaped.
        assert!(c.html.contains("evil&lt;\r\n&gt;group"));
        assert!(!c.html.contains("evil<\r\n>group"));
    }
}
