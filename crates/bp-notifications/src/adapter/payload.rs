// SPDX-License-Identifier: AGPL-3.0-or-later

//! Push-style payload shared by FCM + Web-Push + (eventually) APN.

/// Event-kind tag for FCM `data.type` (`"best_difficulty"`,
/// `"block_found"`, `"device_status"`, `"network_difficulty"`). The
/// mobile / browser receiver routes the notification based on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    BestDifficulty,
    BlockFound,
    DeviceStatus,
    NetworkDifficulty,
}

impl PushKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PushKind::BestDifficulty => "best_difficulty",
            PushKind::BlockFound => "block_found",
            PushKind::DeviceStatus => "device_status",
            PushKind::NetworkDifficulty => "network_difficulty",
        }
    }
}

/// Title + body + optional extra fields for a push notification.
///
/// FCM wires `title`/`body` into `notification.{title,body}` and
/// `extras` into `data{}` (plus the `type` derived from `kind` and the
/// `address` set by the dispatcher). Web-Push / UnifiedPush collapses
/// the same payload into a pipe-joined plain-text body
/// (`title|body|tag`) — that's the format existing push clients
/// (`title|body|difficulty`) already parse.
#[derive(Debug, Clone)]
pub struct PushPayload {
    pub kind: PushKind,
    pub title: String,
    pub body: String,
    /// Free-form trailing tag for the plain-text `title|body|tag`
    /// shape (formatted difficulty or block-height).
    /// FCM passes this as `data.difficulty` for best-diff /
    /// block-found events.
    pub tag: String,
    /// Extra `data{}` fields for FCM payloads. Web-Push ignores these.
    pub extras: Vec<(String, String)>,
}

impl PushPayload {
    /// `"title|body|tag"` — wire shape for UnifiedPush / plain POST.
    pub fn pipe_joined(&self) -> String {
        format!("{}|{}|{}", self.title, self.body, self.tag)
    }
}
