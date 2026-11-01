// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{html, Language};

/// Sats with en-US thousand separators ("12,345").
pub fn format_sats(sats: i64) -> String {
    let abs = sats.unsigned_abs();
    let mut s = format!("{abs}");
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let mut count = 0;
    while let Some(c) = s.pop() {
        if count > 0 && count % 3 == 0 {
            out.push(',');
        }
        out.push(c);
        count += 1;
    }
    let joined: String = out.chars().rev().collect();
    if sats < 0 {
        format!("-{joined}")
    } else {
        joined
    }
}

/// What a block paid its members: `<sats> an <n> Mitglieder`, the amount
/// in bold.
pub fn paid_members(lang: Language, sats: i64, members: usize) -> String {
    let amount = html::bold(&format!("{} sats", format_sats(sats)));
    match (lang, members) {
        (Language::De, 1) => format!("{amount} an 1 Mitglied"),
        (Language::De, n) => format!("{amount} an {n} Mitglieder"),
        (Language::En, 1) => format!("{amount} to 1 member"),
        (Language::En, n) => format!("{amount} to {n} members"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_sats_en_us_separators() {
        assert_eq!(format_sats(0), "0");
        assert_eq!(format_sats(1), "1");
        assert_eq!(format_sats(1_234), "1,234");
        assert_eq!(format_sats(12_345), "12,345");
        assert_eq!(format_sats(123_456), "123,456");
        assert_eq!(format_sats(1_234_567), "1,234,567");
        assert_eq!(format_sats(-1_234), "-1,234");
    }
}
