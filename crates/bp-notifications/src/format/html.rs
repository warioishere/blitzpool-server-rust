// SPDX-License-Identifier: AGPL-3.0-or-later

//! The bot writes its messages as Telegram HTML: a bold title, then
//! `Label: value` lines with the value in bold, addresses in monospace.
//! Telegram renders it; ntfy and app push get the same text as plain text
//! through [`to_plain`]. Every piece the bot did not write itself goes
//! through [`esc`].

/// Escape text for Telegram HTML: `&`, `<` and `>` are what its parser
/// treats as markup.
pub fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn bold(text: &str) -> String {
    format!("<b>{}</b>", esc(text))
}

/// An address (already shortened) in monospace.
pub fn addr(short: &str) -> String {
    format!("<code>{}</code>", esc(short))
}

/// A clickable link that shows `text`, not the URL.
pub fn link(url: &str, text: &str) -> String {
    format!(
        "<a href=\"{}\">{}</a>",
        esc(url).replace('"', "&quot;"),
        esc(text)
    )
}

/// A message title in bold, after an optional emoji.
pub fn title(icon: Option<&str>, text: &str) -> String {
    match icon {
        Some(icon) => format!("{icon} {}", bold(text)),
        None => bold(text),
    }
}

/// A title naming the address it is about.
pub fn title_for(icon: Option<&str>, text: &str, short_address: &str) -> String {
    format!("{} · {}", title(icon, text), addr(short_address))
}

/// `Label: value`, the value in bold.
pub fn row(label: &str, value: &str) -> String {
    format!("{}: {}", esc(label), bold(value))
}

/// The plain text of a bot message, for transports that show no markup:
/// tags dropped, a link as `text (url)`, entities back to their characters.
pub fn to_plain(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut href: Option<String> = None;
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let Some(end) = rest[i..].find('>') else {
            out.push_str(&rest[i..]);
            rest = "";
            break;
        };
        let tag = &rest[i + 1..i + end];
        if let Some(url) = tag
            .strip_prefix("a href=\"")
            .and_then(|t| t.strip_suffix('"'))
        {
            href = Some(url.to_string());
        } else if tag == "/a" {
            if let Some(url) = href.take() {
                out.push_str(&format!(" ({url})"));
            }
        }
        rest = &rest[i + end + 1..];
    }
    out.push_str(rest);
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

/// Whether Telegram accepts `text` as HTML: only the tags the bot uses,
/// properly closed, and no `&` or `<` outside an entity or tag.
#[cfg(test)]
pub fn is_valid_telegram_html(text: &str) -> bool {
    let mut open: Vec<&str> = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(['<', '&', '>']) {
        let tail = &rest[i..];
        if tail.starts_with('>') {
            return false;
        }
        if tail.starts_with('&') {
            let Some(end) = tail.find(';') else {
                return false;
            };
            if !matches!(&tail[..=end], "&amp;" | "&lt;" | "&gt;" | "&quot;") {
                return false;
            }
            rest = &tail[end + 1..];
            continue;
        }
        let Some(end) = tail.find('>') else {
            return false;
        };
        let tag = &tail[1..end];
        if let Some(name) = tag.strip_prefix('/') {
            if open.pop() != Some(name) {
                return false;
            }
        } else if let Some(name) = ["b", "i", "code"].into_iter().find(|t| *t == tag) {
            open.push(name);
        } else if tag.starts_with("a href=\"")
            && tag.ends_with('"')
            && !tag["a href=\"".len()..tag.len() - 1].contains(['"', '<', '>'])
        {
            open.push("a");
        } else {
            return false;
        }
        rest = &tail[end + 1..];
    }
    open.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_markup_characters_stays_text() {
        let line = row("Worker", "<rig & co>");
        assert_eq!(line, "Worker: <b>&lt;rig &amp; co&gt;</b>");
        assert!(is_valid_telegram_html(&line));
        assert_eq!(to_plain(&line), "Worker: <rig & co>");
    }

    #[test]
    fn a_link_shows_its_text_and_keeps_its_url_in_plain() {
        let l = link("https://pool.example/#/app/x?a=1&b=2", "Admin-Panel öffnen");
        assert!(is_valid_telegram_html(&l), "{l}");
        assert_eq!(
            to_plain(&l),
            "Admin-Panel öffnen (https://pool.example/#/app/x?a=1&b=2)"
        );
    }

    #[test]
    fn the_validator_refuses_what_telegram_refuses() {
        assert!(is_valid_telegram_html(&title_for(
            Some("⛏"),
            "Stats",
            "bc1q...586e4"
        )));
        for bad in [
            "a < b", "a & b", "<b>open", "<u>x</u>", "x</b>", "&nbsp;", "a > b",
        ] {
            assert!(!is_valid_telegram_html(bad), "{bad}");
        }
    }
}
