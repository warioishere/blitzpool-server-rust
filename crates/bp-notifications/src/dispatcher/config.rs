// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono_tz::Tz;

/// Static knobs the dispatcher needs at startup that aren't bound to
/// any individual adapter. Adapters carry their own per-transport
/// config (`SmtpConfig`, `TelegramConfig`, …).
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// IANA timezone for device-status timestamps. Default
    /// `Europe/Zurich` — falls back to `UTC` on parse failure.
    pub timezone: Tz,
    /// If `false`, `notify_best_diff` is a no-op. Controlled by
    /// the `NTFY_DIFF_NOTIFICATIONS` env var (which disables ntfy
    /// best-diff spam). We extend the toggle to the whole dispatcher
    /// because the engine never knows in advance which adapters would
    /// handle a given event.
    pub best_diff_enabled: bool,
}

impl DispatcherConfig {
    /// Default — `Europe/Zurich` TZ, best-diff enabled.
    pub fn default_zurich() -> Self {
        Self {
            timezone: chrono_tz::Europe::Zurich,
            best_diff_enabled: true,
        }
    }
}
