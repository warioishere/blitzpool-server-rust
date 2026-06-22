// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coinbase-output capacity operator alert — sent by
//! `CoinbaseCapacityMonitorService` when the active-miner count
//! crosses (or recovers below) a configured threshold of what the
//! current `PPLNS_COINBASE_WEIGHT_BUDGET` can fit.

use super::content::EmailContent;
use super::helpers::{
    escape_html, sanitize_header, shell_html, COLOR_BG, COLOR_MUTED, COLOR_PRIMARY,
    COLOR_PRIMARY_TEXT, COLOR_TEXT,
};

/// Severity of the alert — one of these three is emitted on each capacity tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityAlertLevel {
    Warning,
    Urgent,
    Recovery,
}

/// Inputs for [`render_capacity_alert`]. Recipient (`to:`) is supplied
/// by the adapter when sending, not by the template.
#[derive(Debug, Clone)]
pub struct CapacityAlertContext {
    pub level: CapacityAlertLevel,
    /// Human-readable scope label — e.g. `"PPLNS main pool"` or
    /// `r#"Group "<name>""#`.
    pub scope: String,
    /// Distinct miner addresses currently in the window.
    pub current: u64,
    /// Max outputs the current coinbase weight budget can fit.
    pub max: u64,
    /// `current / max`, 0..=1.
    pub percent: f64,
    /// Active threshold that was crossed, 0..=1.
    pub threshold: f64,
    /// Literal coinbase weight budget used for the ceiling calculation.
    pub coinbase_weight_budget: u64,
    /// ENV var name the operator should bump (e.g.
    /// `"PPLNS_COINBASE_WEIGHT_BUDGET"`).
    pub env_var_name: String,
}

/// Render the capacity-alert email (subject + HTML + text).
pub fn render_capacity_alert(ctx: &CapacityAlertContext) -> EmailContent {
    EmailContent {
        subject: subject(ctx),
        html: render_html(ctx),
        text: render_text(ctx),
    }
}

fn subject(ctx: &CapacityAlertContext) -> String {
    let pct = format!("{:.0}", ctx.percent * 100.0);
    let scope = sanitize_header(&ctx.scope);
    match ctx.level {
        CapacityAlertLevel::Urgent => {
            format!("[Blitz Pool] URGENT: {scope} coinbase capacity at {pct} %")
        }
        CapacityAlertLevel::Recovery => {
            format!("[Blitz Pool] Recovered: {scope} coinbase capacity back to {pct} %")
        }
        CapacityAlertLevel::Warning => {
            format!("[Blitz Pool] Warning: {scope} coinbase capacity at {pct} %")
        }
    }
}

fn render_html(ctx: &CapacityAlertContext) -> String {
    let pct = format!("{:.1}", ctx.percent * 100.0);
    let threshold_pct = format!("{:.0}", ctx.threshold * 100.0);
    let (headline, badge, badge_label) = match ctx.level {
        CapacityAlertLevel::Urgent => ("Coinbase capacity critical", "#FF5252", "URGENT"),
        CapacityAlertLevel::Recovery => ("Coinbase capacity recovered", "#66BB6A", "RECOVERED"),
        CapacityAlertLevel::Warning => ("Coinbase capacity warning", "#FFB74D", "WARNING"),
    };

    let rec_section = if matches!(ctx.level, CapacityAlertLevel::Recovery) {
        String::new()
    } else {
        format!(
            "\n\
<p style=\"margin:24px 0 8px;font-size:14px;font-weight:600;color:{text};\">Recommended action</p>\n\
<p style=\"margin:0 0 16px;font-size:14px;line-height:1.6;color:{text};\">\n  \
Bump both settings to roughly double the current value (e.g. 100 000 or 200 000):\n\
</p>\n\
<p style=\"margin:0 0 16px;padding:12px 16px;background:{bg};border-radius:6px;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};line-height:1.6;\">\n  \
bitcoin.conf: <strong>blockreservedweight={doubled}</strong><br>\n  \
blitzpool.env: <strong>{env}={doubled}</strong>\n\
</p>\n\
<p style=\"margin:0 0 16px;font-size:13px;line-height:1.6;color:{muted};\">\n  \
Then restart bitcoind and the pool. Without an increase, every block above 100 % capacity trims the smallest miners to pending \u{2014} they'll wait longer for their next payout.\n\
</p>",
            text = COLOR_TEXT,
            bg = COLOR_BG,
            primary = COLOR_PRIMARY,
            muted = COLOR_MUTED,
            doubled = escape_html(&(ctx.coinbase_weight_budget * 2).to_string()),
            env = escape_html(&ctx.env_var_name),
        )
    };

    let body = format!(
        "\n\
<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 20px;\">\n  \
<tr><td style=\"background:{badge};color:{primary_text};padding:4px 12px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.1em;\">\n    \
{badge_label}\n  \
</td></tr>\n\
</table>\n\
<h1 style=\"margin:0 0 16px;font-size:22px;font-weight:600;color:{text};\">{headline}</h1>\n\
<p style=\"margin:0 0 24px;font-size:14px;line-height:1.6;color:{text};\">\n  \
{scope} coinbase capacity is currently at <strong style=\"color:{primary};\">{pct} %</strong>\n  \
(threshold {threshold_pct} %).\n\
</p>\n\
<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"margin:0 0 16px;background:{bg};border-radius:6px;\">\n  \
<tr><td style=\"padding:16px;\">\n    \
<p style=\"margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:{muted};\">Active miners</p>\n    \
<p style=\"margin:0 0 16px;font-family:'Roboto Mono',monospace;font-size:18px;color:{text};\">\n      \
{current} / {max}\n    \
</p>\n    \
<p style=\"margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:{muted};\">Coinbase weight budget</p>\n    \
<p style=\"margin:0;font-family:'Roboto Mono',monospace;font-size:13px;color:{primary};\">\n      \
{env}={budget}\n    \
</p>\n  \
</td></tr>\n\
</table>\n\
{rec}\n\
<p style=\"margin:24px 0 0;font-size:12px;color:{muted};\">\n  \
This is an automated operator alert. Next check in roughly one hour. Set\n  \
<code style=\"font-family:'Roboto Mono',monospace;color:{text};\">POOL_CAPACITY_ALERT_ENABLED=false</code>\n  \
to silence.\n\
</p>\n",
        badge = badge,
        primary_text = COLOR_PRIMARY_TEXT,
        badge_label = badge_label,
        text = COLOR_TEXT,
        primary = COLOR_PRIMARY,
        bg = COLOR_BG,
        muted = COLOR_MUTED,
        headline = escape_html(headline),
        scope = escape_html(&ctx.scope),
        pct = escape_html(&pct),
        threshold_pct = escape_html(&threshold_pct),
        current = escape_html(&ctx.current.to_string()),
        max = escape_html(&ctx.max.to_string()),
        env = escape_html(&ctx.env_var_name),
        budget = escape_html(&ctx.coinbase_weight_budget.to_string()),
        rec = rec_section,
    );
    shell_html(headline, &body)
}

fn render_text(ctx: &CapacityAlertContext) -> String {
    let pct = format!("{:.1}", ctx.percent * 100.0);
    let threshold_pct = format!("{:.0}", ctx.threshold * 100.0);
    let head = match ctx.level {
        CapacityAlertLevel::Urgent => {
            format!("URGENT: {} coinbase capacity critical", ctx.scope)
        }
        CapacityAlertLevel::Recovery => {
            format!("RECOVERED: {} coinbase capacity back to normal", ctx.scope)
        }
        CapacityAlertLevel::Warning => {
            format!("WARNING: {} coinbase capacity threshold crossed", ctx.scope)
        }
    };

    let mut lines: Vec<String> = vec![
        head,
        String::new(),
        format!("Current: {} / {} miners  ({} %)", ctx.current, ctx.max, pct),
        format!("Threshold: {threshold_pct} %"),
        format!(
            "Budget: {}={}",
            ctx.env_var_name, ctx.coinbase_weight_budget
        ),
        String::new(),
    ];
    if !matches!(ctx.level, CapacityAlertLevel::Recovery) {
        let doubled = ctx.coinbase_weight_budget * 2;
        lines.push(format!("Recommended: bump both to {doubled}"));
        lines.push(format!("  bitcoin.conf: blockreservedweight={doubled}"));
        lines.push(format!("  blitzpool.env: {}={doubled}", ctx.env_var_name));
        lines.push("Then restart bitcoind + pool.".to_string());
        lines.push(String::new());
    }
    lines.push("Next check in ~1h.".to_string());
    lines.push("Silence with POOL_CAPACITY_ALERT_ENABLED=false.".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warning_ctx() -> CapacityAlertContext {
        CapacityAlertContext {
            level: CapacityAlertLevel::Warning,
            scope: "PPLNS main pool".to_string(),
            current: 480,
            max: 600,
            percent: 0.8,
            threshold: 0.8,
            coinbase_weight_budget: 50_000,
            env_var_name: "PPLNS_COINBASE_WEIGHT_BUDGET".to_string(),
        }
    }

    #[test]
    fn warning_subject() {
        let c = render_capacity_alert(&warning_ctx());
        assert_eq!(
            c.subject,
            "[Blitz Pool] Warning: PPLNS main pool coinbase capacity at 80 %"
        );
    }

    #[test]
    fn urgent_subject() {
        let mut x = warning_ctx();
        x.level = CapacityAlertLevel::Urgent;
        x.percent = 0.96;
        let c = render_capacity_alert(&x);
        assert_eq!(
            c.subject,
            "[Blitz Pool] URGENT: PPLNS main pool coinbase capacity at 96 %"
        );
    }

    #[test]
    fn recovery_subject() {
        let mut x = warning_ctx();
        x.level = CapacityAlertLevel::Recovery;
        x.percent = 0.65;
        let c = render_capacity_alert(&x);
        assert_eq!(
            c.subject,
            "[Blitz Pool] Recovered: PPLNS main pool coinbase capacity back to 65 %"
        );
    }

    #[test]
    fn subject_sanitizes_scope() {
        let mut x = warning_ctx();
        x.scope = "evil\r\nBcc:".to_string();
        let s = render_capacity_alert(&x).subject;
        assert!(!s.contains('\r'));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn html_one_decimal_pct_and_threshold() {
        let mut x = warning_ctx();
        x.percent = 0.875;
        x.threshold = 0.8;
        let c = render_capacity_alert(&x);
        assert!(c
            .html
            .contains("currently at <strong style=\"color:#9FA8DA;\">87.5 %</strong>"));
        assert!(c.html.contains("(threshold 80 %)"));
    }

    #[test]
    fn html_warning_has_recommendation_with_double_budget() {
        let c = render_capacity_alert(&warning_ctx());
        assert!(c.html.contains("Recommended action"));
        assert!(c
            .html
            .contains("bitcoin.conf: <strong>blockreservedweight=100000</strong>"));
        assert!(c
            .html
            .contains("blitzpool.env: <strong>PPLNS_COINBASE_WEIGHT_BUDGET=100000</strong>"));
    }

    #[test]
    fn html_urgent_has_red_badge() {
        let mut x = warning_ctx();
        x.level = CapacityAlertLevel::Urgent;
        let c = render_capacity_alert(&x);
        assert!(c.html.contains("background:#FF5252"));
        assert!(c.html.contains(">URGENT</td>") || c.html.contains("URGENT\n  </td>"));
        assert!(c.html.contains("Coinbase capacity critical</h1>"));
    }

    #[test]
    fn html_recovery_has_green_badge_and_no_recommendation() {
        let mut x = warning_ctx();
        x.level = CapacityAlertLevel::Recovery;
        let c = render_capacity_alert(&x);
        assert!(c.html.contains("background:#66BB6A"));
        assert!(c.html.contains("RECOVERED"));
        assert!(c.html.contains("Coinbase capacity recovered</h1>"));
        assert!(!c.html.contains("Recommended action"));
        assert!(!c.html.contains("Then restart bitcoind"));
    }

    #[test]
    fn html_warning_has_orange_badge() {
        let c = render_capacity_alert(&warning_ctx());
        assert!(c.html.contains("background:#FFB74D"));
        assert!(c.html.contains("WARNING"));
        assert!(c.html.contains("Coinbase capacity warning</h1>"));
    }

    #[test]
    fn html_shows_current_max_and_budget_line() {
        let c = render_capacity_alert(&warning_ctx());
        assert!(c.html.contains("480 / 600"));
        assert!(c.html.contains("PPLNS_COINBASE_WEIGHT_BUDGET=50000"));
        assert!(c.html.contains("POOL_CAPACITY_ALERT_ENABLED=false"));
    }

    #[test]
    fn text_warning_includes_full_recommendation_block() {
        let c = render_capacity_alert(&warning_ctx());
        let expected = "WARNING: PPLNS main pool coinbase capacity threshold crossed\n\
\n\
Current: 480 / 600 miners  (80.0 %)\n\
Threshold: 80 %\n\
Budget: PPLNS_COINBASE_WEIGHT_BUDGET=50000\n\
\n\
Recommended: bump both to 100000\n  \
bitcoin.conf: blockreservedweight=100000\n  \
blitzpool.env: PPLNS_COINBASE_WEIGHT_BUDGET=100000\n\
Then restart bitcoind + pool.\n\
\n\
Next check in ~1h.\n\
Silence with POOL_CAPACITY_ALERT_ENABLED=false.";
        assert_eq!(c.text, expected);
    }

    #[test]
    fn text_recovery_skips_recommendation_block() {
        let mut x = warning_ctx();
        x.level = CapacityAlertLevel::Recovery;
        x.percent = 0.65;
        let c = render_capacity_alert(&x);
        assert!(c
            .text
            .starts_with("RECOVERED: PPLNS main pool coinbase capacity back to normal\n"));
        assert!(!c.text.contains("Recommended:"));
        assert!(!c.text.contains("bitcoin.conf:"));
        assert!(c.text.contains("Current: 480 / 600 miners  (65.0 %)"));
        assert!(c
            .text
            .ends_with("Silence with POOL_CAPACITY_ALERT_ENABLED=false."));
    }

    #[test]
    fn text_urgent_head_says_critical() {
        let mut x = warning_ctx();
        x.level = CapacityAlertLevel::Urgent;
        x.percent = 0.97;
        let c = render_capacity_alert(&x);
        assert!(c
            .text
            .starts_with("URGENT: PPLNS main pool coinbase capacity critical\n"));
        assert!(c.text.contains("Current: 480 / 600 miners  (97.0 %)"));
    }

    #[test]
    fn html_scope_is_html_escaped_in_body() {
        let mut x = warning_ctx();
        x.scope = "<group>".to_string();
        let c = render_capacity_alert(&x);
        assert!(c.html.contains("&lt;group&gt; coinbase capacity"));
        assert!(!c.html.contains("<group> coinbase capacity"));
    }
}
