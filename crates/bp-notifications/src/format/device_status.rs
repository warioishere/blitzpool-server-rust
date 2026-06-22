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
}
