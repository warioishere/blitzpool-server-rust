// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-language device-status message builder + timezone formatter.
//!
//! Consolidates the duplicated de/en formatting for Telegram, ntfy,
//! and push-notification paths into a single helper. The dispatcher
//! calls this and pipes the result into whichever adapter is being
//! used.

use chrono::{DateTime, Utc};

use super::Language;

/// Inputs for [`DeviceStatusText::build`].
#[derive(Debug, Clone)]
pub struct DeviceStatusArgs<'a> {
    pub language: Language,
    /// Pre-formatted local timestamp (use [`format_device_time`] to
    /// produce this — separated so the caller can format once per
    /// chat and reuse across many subscribers).
    pub time_formatted: &'a str,
    pub user_agent: Option<&'a str>,
    pub worker_name: Option<&'a str>,
    pub is_online: bool,
    pub is_returning: bool,
    /// Trailing " – Adresse <fmt>" / " – address <fmt>" suffix used
    /// in multi-address Telegram chats. `None` skips the suffix
    /// (single-address chats / ntfy).
    pub address_suffix: Option<&'a str>,
}

/// Output triple — most callers pick by `args.language` and discard
/// the other variant. Keeping both lets the dispatcher hand the same
/// result to multiple adapters without rebuilding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatusText {
    pub de: String,
    pub en: String,
}

impl DeviceStatusText {
    pub fn build(args: &DeviceStatusArgs<'_>) -> Self {
        let ua_trim = args.user_agent.map(str::trim).filter(|s| !s.is_empty());
        let worker_trim = args.worker_name.map(str::trim).filter(|s| !s.is_empty());

        let ua_de = ua_trim.unwrap_or("unbekannt");
        let ua_en = ua_trim.unwrap_or("unknown");
        let worker_de = worker_trim.unwrap_or("unbekannt");
        let worker_en = worker_trim.unwrap_or("unknown");
        let suffix = args.address_suffix.unwrap_or("");

        let de = if args.is_online {
            let returning = if args.is_returning { "wieder " } else { "" };
            format!(
                "\u{1f4f6} Gerät {ua_de} (Worker {worker_de}) ist seit {time} {returning}online{suffix}.",
                time = args.time_formatted,
                suffix = suffix,
            )
        } else {
            format!(
                "\u{1f4f4} Gerät {ua_de} (Worker {worker_de}) ist seit {time} offline{suffix}.",
                time = args.time_formatted,
                suffix = suffix,
            )
        };
        let en = if args.is_online {
            let returning = if args.is_returning { "back " } else { "" };
            format!(
                "\u{1f4f6} Device with {ua_en} (worker {worker_en}) {returning}online at {time}{suffix}.",
                time = args.time_formatted,
                suffix = suffix,
            )
        } else {
            format!(
                "\u{1f4f4} Device with {ua_en} (worker {worker_en}) went offline at {time}{suffix}.",
                time = args.time_formatted,
                suffix = suffix,
            )
        };
        DeviceStatusText { de, en }
    }

    pub fn pick(&self, lang: Language) -> &str {
        match lang {
            Language::De => &self.de,
            Language::En => &self.en,
        }
    }
}

/// At most this many worker names are spelled out; the rest are
/// summarised as a count. Keeps a farm-sized batch inside one readable
/// notification instead of a wall of names.
const MAX_NAMES: usize = 6;

/// Inputs for [`DevicePartialText::build`].
#[derive(Debug, Clone)]
pub struct DevicePartialArgs<'a> {
    pub language: Language,
    pub time_formatted: &'a str,
    pub worker_name: Option<&'a str>,
    /// Sessions still hashing, and how many there were before.
    pub remaining: usize,
    pub before: usize,
    pub address_suffix: Option<&'a str>,
}

/// Some of a worker's rigs are gone; the worker is still up.
///
/// Deliberately worded so it can never read as an outage: the owner of
/// three rigs under one name has lost one, not all three, and a rental
/// source whose count dipped has not ended its rental.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePartialText {
    pub de: String,
    pub en: String,
}

impl DevicePartialText {
    pub fn build(args: &DevicePartialArgs<'_>) -> Self {
        let worker_trim = args.worker_name.map(str::trim).filter(|s| !s.is_empty());
        let worker_de = worker_trim.unwrap_or("unbekannt");
        let worker_en = worker_trim.unwrap_or("unknown");
        let suffix = args.address_suffix.unwrap_or("");
        let gone = args.before.saturating_sub(args.remaining);
        DevicePartialText {
            de: format!(
                "\u{26a0}\u{fe0f} Worker {worker_de}: {gone} von {before} Geräten weg, {remaining} noch aktiv – Stand {time}{suffix}.",
                before = args.before,
                remaining = args.remaining,
                time = args.time_formatted,
            ),
            en: format!(
                "\u{26a0}\u{fe0f} Worker {worker_en}: {gone} of {before} devices gone, {remaining} still hashing – as of {time}{suffix}.",
                before = args.before,
                remaining = args.remaining,
                time = args.time_formatted,
            ),
        }
    }

    pub fn pick(&self, lang: Language) -> &str {
        match lang {
            Language::De => &self.de,
            Language::En => &self.en,
        }
    }
}

/// Inputs for [`DeviceAggregateText::build`] — the collapsed form used
/// when one address settles several transitions inside the coalescing
/// window.
#[derive(Debug, Clone)]
pub struct DeviceAggregateArgs<'a> {
    pub language: Language,
    /// Pre-formatted local timestamp, as for [`DeviceStatusArgs`].
    pub time_formatted: &'a str,
    pub went_offline: &'a [String],
    /// Workers that returned after having been reported offline.
    pub came_back: &'a [String],
    /// Workers seen for the first time. Kept apart from `came_back`
    /// because calling a brand-new miner "back online" tells the reader
    /// it recovered from an outage they were never notified about.
    pub first_seen: &'a [String],
    /// `(worker, remaining, before)` for workers that lost some rigs but
    /// are still hashing.
    pub reduced: &'a [(String, usize, usize)],
    pub address_suffix: Option<&'a str>,
}

/// Aggregate counterpart to [`DeviceStatusText`], same de/en shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAggregateText {
    pub de: String,
    pub en: String,
}

impl DeviceAggregateText {
    pub fn build(args: &DeviceAggregateArgs<'_>) -> Self {
        let suffix = args.address_suffix.unwrap_or("");

        let mut de_parts = Vec::new();
        let mut en_parts = Vec::new();
        if !args.went_offline.is_empty() {
            let n = args.went_offline.len();
            de_parts.push(format!(
                "\u{1f4f4} {n} Worker offline ({})",
                join_names(args.went_offline, Language::De)
            ));
            en_parts.push(format!(
                "\u{1f4f4} {n} {} offline ({})",
                plural_worker_en(n),
                join_names(args.went_offline, Language::En)
            ));
        }
        if !args.came_back.is_empty() {
            let n = args.came_back.len();
            de_parts.push(format!(
                "\u{1f4f6} {n} Worker wieder online ({})",
                join_names(args.came_back, Language::De)
            ));
            en_parts.push(format!(
                "\u{1f4f6} {n} {} back online ({})",
                plural_worker_en(n),
                join_names(args.came_back, Language::En)
            ));
        }
        if !args.reduced.is_empty() {
            for (worker, remaining, before) in args.reduced {
                let gone = before.saturating_sub(*remaining);
                de_parts.push(format!(
                    "\u{26a0}\u{fe0f} {worker}: {gone} von {before} weg ({remaining} aktiv)"
                ));
                en_parts.push(format!(
                    "\u{26a0}\u{fe0f} {worker}: {gone} of {before} gone ({remaining} hashing)"
                ));
            }
        }
        if !args.first_seen.is_empty() {
            let n = args.first_seen.len();
            de_parts.push(format!(
                "\u{2728} {n} Worker neu ({})",
                join_names(args.first_seen, Language::De)
            ));
            en_parts.push(format!(
                "\u{2728} {n} new {} ({})",
                plural_worker_en(n),
                join_names(args.first_seen, Language::En)
            ));
        }

        DeviceAggregateText {
            de: format!(
                "{} – Stand {}{}.",
                de_parts.join(" \u{b7} "),
                args.time_formatted,
                suffix
            ),
            en: format!(
                "{} – as of {}{}.",
                en_parts.join(" \u{b7} "),
                args.time_formatted,
                suffix
            ),
        }
    }

    pub fn pick(&self, lang: Language) -> &str {
        match lang {
            Language::De => &self.de,
            Language::En => &self.en,
        }
    }
}

fn plural_worker_en(n: usize) -> &'static str {
    if n == 1 {
        "worker"
    } else {
        "workers"
    }
}

/// Comma-join up to [`MAX_NAMES`] names, then summarise the remainder.
fn join_names(names: &[String], language: Language) -> String {
    let shown: Vec<&str> = names
        .iter()
        .take(MAX_NAMES)
        .map(|s| {
            let t = s.trim();
            if t.is_empty() {
                match language {
                    Language::De => "unbekannt",
                    Language::En => "unknown",
                }
            } else {
                t
            }
        })
        .collect();
    let joined = shown.join(", ");
    let rest = names.len().saturating_sub(MAX_NAMES);
    if rest == 0 {
        return joined;
    }
    match language {
        Language::De => format!("{joined} … +{rest} weitere"),
        Language::En => format!("{joined} … +{rest} more"),
    }
}

/// Format a UTC instant in the per-deployment timezone (e.g.
/// `Europe/Zurich`) as a short date + short time.
///
/// - `de` locale: `"01.05.26, 14:30"` (dd.MM.yy + HH:mm)
/// - `en` locale: `"5/1/26, 2:30 PM"` (M/d/yy + h:mm AM/PM)
pub fn format_device_time(
    tz: chrono_tz::Tz,
    event_utc: DateTime<Utc>,
    language: Language,
) -> String {
    let local = event_utc.with_timezone(&tz);
    match language {
        Language::De => local.format("%d.%m.%y, %H:%M").to_string(),
        Language::En => local.format("%-m/%-d/%y, %-I:%M %p").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn args_base<'a>(time: &'a str) -> DeviceStatusArgs<'a> {
        DeviceStatusArgs {
            language: Language::De,
            time_formatted: time,
            user_agent: Some("BitAxe-1.2.0"),
            worker_name: Some("axe01"),
            is_online: true,
            is_returning: false,
            address_suffix: None,
        }
    }

    #[test]
    fn online_de_no_returning_no_suffix() {
        let text = DeviceStatusText::build(&args_base("01.05.26, 14:30"));
        assert_eq!(
            text.de,
            "\u{1f4f6} Gerät BitAxe-1.2.0 (Worker axe01) ist seit 01.05.26, 14:30 online."
        );
    }

    #[test]
    fn online_en_with_returning() {
        let mut a = args_base("5/1/26, 2:30 PM");
        a.language = Language::En;
        a.is_returning = true;
        let text = DeviceStatusText::build(&a);
        assert_eq!(
            text.en,
            "\u{1f4f6} Device with BitAxe-1.2.0 (worker axe01) back online at 5/1/26, 2:30 PM."
        );
    }

    #[test]
    fn offline_with_address_suffix() {
        let mut a = args_base("01.05.26, 14:30");
        a.is_online = false;
        a.address_suffix = Some(" – Adresse bc1q...xyz");
        let text = DeviceStatusText::build(&a);
        assert_eq!(
            text.de,
            "\u{1f4f4} Gerät BitAxe-1.2.0 (Worker axe01) ist seit 01.05.26, 14:30 offline – Adresse bc1q...xyz."
        );
    }

    #[test]
    fn missing_ua_and_worker_use_unbekannt_unknown() {
        let mut a = args_base("01.05.26, 14:30");
        a.user_agent = None;
        a.worker_name = None;
        let text = DeviceStatusText::build(&a);
        assert!(text.de.contains("Gerät unbekannt (Worker unbekannt)"));
        assert!(text.en.contains("Device with unknown (worker unknown)"));
    }

    #[test]
    fn empty_strings_treated_as_missing() {
        let mut a = args_base("01.05.26, 14:30");
        a.user_agent = Some("");
        a.worker_name = Some("   ");
        let text = DeviceStatusText::build(&a);
        assert!(text.de.contains("Gerät unbekannt"));
        assert!(text.en.contains("worker unknown"));
    }

    #[test]
    fn pick_returns_per_language_variant() {
        let text = DeviceStatusText::build(&args_base("01.05.26, 14:30"));
        assert_eq!(text.pick(Language::De), &text.de);
        assert_eq!(text.pick(Language::En), &text.en);
    }

    #[test]
    fn format_device_time_de_short_format() {
        // 2026-05-01 12:30:00 UTC, Europe/Zurich (UTC+2 in May) → 14:30.
        let utc = Utc.with_ymd_and_hms(2026, 5, 1, 12, 30, 0).unwrap();
        let zurich: chrono_tz::Tz = "Europe/Zurich".parse().unwrap();
        assert_eq!(
            format_device_time(zurich, utc, Language::De),
            "01.05.26, 14:30"
        );
    }

    #[test]
    fn format_device_time_en_uses_12h_clock() {
        let utc = Utc.with_ymd_and_hms(2026, 5, 1, 12, 30, 0).unwrap();
        let zurich: chrono_tz::Tz = "Europe/Zurich".parse().unwrap();
        // 14:30 Zurich → 2:30 PM.
        assert_eq!(
            format_device_time(zurich, utc, Language::En),
            "5/1/26, 2:30 PM"
        );
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    const NO_NAMES: &[String] = &[];

    fn agg_args<'a>(
        time: &'a str,
        off: &'a [String],
        back: &'a [String],
    ) -> DeviceAggregateArgs<'a> {
        DeviceAggregateArgs {
            language: Language::De,
            time_formatted: time,
            went_offline: off,
            came_back: back,
            first_seen: NO_NAMES,
            reduced: &[],
            address_suffix: None,
        }
    }

    /// First sightings get their own clause — telling someone a brand-new
    /// miner is "back online" claims an outage they were never told about.
    #[test]
    fn aggregate_names_first_sightings_separately() {
        let back = names(&["old"]);
        let fresh = names(&["new1", "new2"]);
        let t = DeviceAggregateText::build(&DeviceAggregateArgs {
            language: Language::De,
            time_formatted: "01.05.26, 14:30",
            went_offline: NO_NAMES,
            came_back: &back,
            first_seen: &fresh,
            reduced: &[],
            address_suffix: None,
        });
        assert!(t.de.contains("1 Worker wieder online (old)"), "{}", t.de);
        assert!(t.de.contains("2 Worker neu (new1, new2)"), "{}", t.de);
        assert!(t.en.contains("1 worker back online (old)"), "{}", t.en);
        assert!(t.en.contains("2 new workers (new1, new2)"), "{}", t.en);
    }

    #[test]
    fn aggregate_offline_only_names_every_worker() {
        let off = names(&["axe01", "axe02", "axe03"]);
        let t = DeviceAggregateText::build(&agg_args("01.05.26, 14:30", &off, &[]));
        assert_eq!(
            t.de,
            "\u{1f4f4} 3 Worker offline (axe01, axe02, axe03) – Stand 01.05.26, 14:30."
        );
        assert_eq!(
            t.en,
            "\u{1f4f4} 3 workers offline (axe01, axe02, axe03) – as of 01.05.26, 14:30."
        );
    }

    /// A batch that moves in both directions must say so in one message —
    /// that is the whole point of collapsing.
    #[test]
    fn aggregate_reports_both_directions_in_one_line() {
        let off = names(&["a", "b"]);
        let on = names(&["c"]);
        let t = DeviceAggregateText::build(&agg_args("01.05.26, 14:30", &off, &on));
        assert_eq!(
            t.de,
            "\u{1f4f4} 2 Worker offline (a, b) \u{b7} \u{1f4f6} 1 Worker wieder online (c) \
             – Stand 01.05.26, 14:30."
        );
        // English singular must not read "1 workers".
        assert!(t.en.contains("1 worker back online (c)"), "{}", t.en);
    }

    /// A farm-sized batch must stay readable: names are capped and the
    /// remainder is counted, never silently dropped.
    #[test]
    fn aggregate_caps_the_name_list_and_counts_the_rest() {
        let off = names(&["w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9"]);
        let t = DeviceAggregateText::build(&agg_args("01.05.26, 14:30", &off, &[]));
        assert!(t
            .de
            .starts_with("\u{1f4f4} 9 Worker offline (w1, w2, w3, w4, w5, w6 … +3 weitere)"));
        assert!(t.en.contains("… +3 more"), "{}", t.en);
        assert!(
            !t.de.contains("w7"),
            "capped names must not leak into the list"
        );
    }

    #[test]
    fn aggregate_appends_the_address_suffix() {
        let off = names(&["a", "b"]);
        let mut args = agg_args("01.05.26, 14:30", &off, &[]);
        args.address_suffix = Some(" – Adresse bc1q...xyz");
        let t = DeviceAggregateText::build(&args);
        assert!(t.de.ends_with(" – Adresse bc1q...xyz."), "{}", t.de);
    }

    /// A worker name is optional on the wire; an empty one must render as
    /// a placeholder rather than an empty pair of commas.
    #[test]
    fn aggregate_renders_a_blank_worker_name_as_a_placeholder() {
        let off = names(&["", "b"]);
        let t = DeviceAggregateText::build(&agg_args("01.05.26, 14:30", &off, &[]));
        assert!(t.de.contains("(unbekannt, b)"), "{}", t.de);
        assert!(t.en.contains("(unknown, b)"), "{}", t.en);
    }
}
