// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared HTML helpers + color palette for the email templates.
//!
//! Inline-styled HTML — email clients strip `<style>` tags so colour /
//! font definitions live on every element. Card stays on the dashboard
//! `mdc-dark-indigo` palette (dark card on light page) so the email
//! reads as "themed app", not "phishing template" — ML spam classifiers
//! (Gmail in particular) treat fully-dark `<body>` as a mild risk
//! signal; light page + dark card is the safe shape.

use chrono::{DateTime, Utc};

// Theme constants.
pub(crate) const COLOR_PAGE: &str = "#f5f5f7";
pub(crate) const COLOR_BG: &str = "#1e1e1e";
pub(crate) const COLOR_CARD: &str = "#2a2a2a";
pub(crate) const COLOR_BORDER: &str = "#3a3a3a";
pub(crate) const COLOR_PRIMARY: &str = "#9FA8DA";
pub(crate) const COLOR_PRIMARY_TEXT: &str = "#1a1a1a";
pub(crate) const COLOR_TEXT: &str = "#ffffff";
pub(crate) const COLOR_MUTED: &str = "#9e9e9e";

/// HTML-entity-escape the 5 chars `& < > " '`.
pub(crate) fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Attribute-safe escape — `&` and `"` only. Used inside
/// `href="…"` where `<` `>` `'` are valid in URL contexts and we want
/// to keep the output compact.
pub(crate) fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Defense-in-depth for email-header injection — strips `\r \n \0` and
/// truncates to 200 chars. Applied to dynamic parts of `Subject:` lines
/// (e.g. group names) even though the group-name input is already
/// validated upstream at create-time.
pub(crate) fn sanitize_header(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if matches!(c, '\r' | '\n' | '\0') {
                ' '
            } else {
                c
            }
        })
        .collect();
    // 200 char cap; char-aware, not byte-aware (emails practically
    // only contain ASCII / BMP chars).
    if cleaned.chars().count() <= 200 {
        cleaned
    } else {
        cleaned.chars().take(200).collect()
    }
}

/// Render the shared shell — `<!doctype html>` + email-safe table
/// layout + Blitz Pool header + footer disclaimer + injected `body`.
pub(crate) fn shell_html(title: &str, body_html: &str) -> String {
    format!(
        "<!doctype html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>{title}</title>\n\
</head>\n\
<body style=\"margin:0;padding:0;background:{page};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:{text};\">\n\
<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"background:{page};padding:32px 16px;\">\n  \
<tr><td align=\"center\">\n    \
<table role=\"presentation\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" style=\"max-width:600px;width:100%;background:{card};border:1px solid {border};border-radius:8px;overflow:hidden;\">\n      \
<tr><td style=\"padding:24px 32px;border-bottom:1px solid {border};\">\n        \
<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\">\n          \
<tr>\n            \
<td style=\"font-size:20px;font-weight:600;color:{text};\">\u{26a1} Blitz Pool</td>\n            \
<td align=\"right\" style=\"font-size:12px;color:{muted};\">Mining Pool</td>\n          \
</tr>\n        \
</table>\n      \
</td></tr>\n      \
<tr><td style=\"padding:32px;\">\n        {body}\n      \
</td></tr>\n      \
<tr><td style=\"padding:20px 32px;border-top:1px solid {border};font-size:11px;color:{muted};line-height:1.5;\">\n        \
This is a transactional email from Blitz Pool. If you did not expect this message you can safely ignore it \u{2014} no action will be taken.\n      \
</td></tr>\n    \
</table>\n  \
</td></tr>\n\
</table>\n\
</body>\n\
</html>",
        title = escape_html(title),
        page = COLOR_PAGE,
        text = COLOR_TEXT,
        card = COLOR_CARD,
        border = COLOR_BORDER,
        muted = COLOR_MUTED,
        body = body_html,
    )
}

/// Inline-styled button anchor. `primary=true` uses the indigo fill,
/// `primary=false` is a transparent outline button (currently unused
/// by any template but kept for completeness).
pub(crate) fn button_html(href: &str, label: &str, primary: bool) -> String {
    if primary {
        format!(
            "<a href=\"{href}\" style=\"display:inline-block;background:{bg};color:{text};padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;\">{label}</a>",
            href = escape_attr(href),
            bg = COLOR_PRIMARY,
            text = COLOR_PRIMARY_TEXT,
            label = escape_html(label),
        )
    } else {
        format!(
            "<a href=\"{href}\" style=\"display:inline-block;background:transparent;color:{text};padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:500;font-size:14px;border:1px solid {border};\">{label}</a>",
            href = escape_attr(href),
            text = COLOR_TEXT,
            border = COLOR_BORDER,
            label = escape_html(label),
        )
    }
}

/// `Date.prototype.toUTCString()` equivalent — RFC 7231 `IMF-fixdate`,
/// e.g. `"Sat, 16 May 2026 12:34:56 GMT"`. Two-digit zero-padded day
/// matches V8 / JavaScriptCore behaviour. Used for `expires_at`
/// rendering inside the templates.
pub(crate) fn format_utc_string(ts: &DateTime<Utc>) -> String {
    ts.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn escape_html_handles_all_five_chars() {
        assert_eq!(escape_html("&"), "&amp;");
        assert_eq!(escape_html("<"), "&lt;");
        assert_eq!(escape_html(">"), "&gt;");
        assert_eq!(escape_html("\""), "&quot;");
        assert_eq!(escape_html("'"), "&#39;");
    }

    #[test]
    fn escape_html_preserves_non_special_chars() {
        assert_eq!(escape_html("hello world"), "hello world");
        assert_eq!(escape_html("Blitz Pool \u{26a1}"), "Blitz Pool \u{26a1}");
        assert_eq!(escape_html("bc1q…address"), "bc1q…address");
    }

    #[test]
    fn escape_html_chains_multiple_escapes_correctly() {
        // Ampersand must be escaped FIRST — escaping `<` before `&`
        // would double-escape the `&amp;`.
        assert_eq!(
            escape_html("<script>alert(\"x&y\")</script>"),
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;"
        );
    }

    #[test]
    fn escape_attr_handles_only_amp_and_quote() {
        assert_eq!(escape_attr("&"), "&amp;");
        assert_eq!(escape_attr("\""), "&quot;");
        assert_eq!(escape_attr("'"), "'"); // not escaped
        assert_eq!(escape_attr("<"), "<"); // not escaped
        assert_eq!(escape_attr(">"), ">"); // not escaped
    }

    #[test]
    fn escape_attr_keeps_query_strings_intact_after_amp_escape() {
        assert_eq!(
            escape_attr("https://example.com/?a=1&b=2"),
            "https://example.com/?a=1&amp;b=2"
        );
    }

    #[test]
    fn sanitize_header_strips_newlines_and_nulls() {
        assert_eq!(
            sanitize_header("evil\r\nSubject: hijack"),
            "evil  Subject: hijack"
        );
        assert_eq!(sanitize_header("with\0null"), "with null");
    }

    #[test]
    fn sanitize_header_truncates_at_200_chars() {
        let long = "a".repeat(250);
        assert_eq!(sanitize_header(&long).chars().count(), 200);
    }

    #[test]
    fn sanitize_header_passthrough_for_short_clean_input() {
        assert_eq!(sanitize_header("MyGroup"), "MyGroup");
        assert_eq!(sanitize_header(""), "");
    }

    #[test]
    fn shell_html_wraps_body_and_brands() {
        let out = shell_html("Hello", "<p>body</p>");
        assert!(out.starts_with("<!doctype html>"));
        assert!(out.contains("<title>Hello</title>"));
        assert!(out.contains("\u{26a1} Blitz Pool"));
        assert!(out.contains("<p>body</p>"));
        assert!(out.contains(
            "This is a transactional email from Blitz Pool. If you did not expect this message"
        ));
    }

    #[test]
    fn shell_html_escapes_title() {
        let out = shell_html("<script>", "");
        assert!(out.contains("<title>&lt;script&gt;</title>"));
    }

    #[test]
    fn button_html_primary_has_indigo_fill_and_escapes_label() {
        let out = button_html("https://x.test/?a=1&b=2", "Click <me>", true);
        // href is attr-escaped (& → &amp;), label is html-escaped (< → &lt;).
        assert!(out.contains("href=\"https://x.test/?a=1&amp;b=2\""));
        assert!(out.contains(">Click &lt;me&gt;</a>"));
        assert!(out.contains(COLOR_PRIMARY));
    }

    #[test]
    fn button_html_outline_is_transparent_with_border() {
        let out = button_html("https://x.test", "Decline", false);
        assert!(out.contains("background:transparent"));
        assert!(out.contains(&format!("border:1px solid {COLOR_BORDER}")));
        // No primary-fill colour in the inline style.
        assert!(!out.contains(&format!("background:{COLOR_PRIMARY}")));
    }

    #[test]
    fn format_utc_string_matches_js_to_utc_string_shape() {
        let dt = Utc.with_ymd_and_hms(2026, 5, 16, 12, 34, 56).unwrap();
        assert_eq!(format_utc_string(&dt), "Sat, 16 May 2026 12:34:56 GMT");
    }

    #[test]
    fn format_utc_string_zero_pads_single_digit_day() {
        let dt = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        assert_eq!(format_utc_string(&dt), "Mon, 05 Jan 2026 00:00:00 GMT");
    }
}
