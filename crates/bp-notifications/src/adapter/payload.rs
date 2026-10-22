// SPDX-License-Identifier: AGPL-3.0-or-later

//! Push-style payload shared by FCM + Web-Push.

/// Event-kind tag for FCM `data.type` (`"best_difficulty"`,
/// `"block_found"`, `"device_status"`, `"network_difficulty"`,
/// `"group_join_request"`). The mobile / browser receiver routes the
/// notification based on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    BestDifficulty,
    BlockFound,
    DeviceStatus,
    NetworkDifficulty,
    GroupJoinRequest,
}

impl PushKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PushKind::BestDifficulty => "best_difficulty",
            PushKind::BlockFound => "block_found",
            PushKind::DeviceStatus => "device_status",
            PushKind::NetworkDifficulty => "network_difficulty",
            PushKind::GroupJoinRequest => "group_join_request",
        }
    }
}

/// Title + body + optional extra fields for a push notification. FCM maps
/// `extras` into `data{}`; Web-Push / UnifiedPush collapses it to the
/// `title|body|tag` plain text existing push clients parse.
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
    /// `"title|body|tag"` — wire shape for UnifiedPush / plain POST. A `|`
    /// inside a field (free text such as a Team or worker name) becomes `¦`,
    /// so the receiver's split still yields exactly these three fields.
    pub fn pipe_joined(&self) -> String {
        let field = |s: &str| s.replace('|', "\u{a6}");
        format!(
            "{}|{}|{}",
            field(&self.title),
            field(&self.body),
            field(&self.tag)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(title: &str, body: &str, tag: &str) -> PushPayload {
        PushPayload {
            kind: PushKind::DeviceStatus,
            title: title.to_string(),
            body: body.to_string(),
            tag: tag.to_string(),
            extras: Vec::new(),
        }
    }

    /// Free text holding a `|` (a Team name, a worker name) stays inside its
    /// field, so the receiver still splits into title, body and tag.
    #[test]
    fn a_pipe_in_free_text_does_not_add_a_field() {
        let wire = payload("New join request", "New join request in A|B", "").pipe_joined();
        assert_eq!(wire.split('|').count(), 3, "wire was: {wire}");
        assert_eq!(wire, "New join request|New join request in A\u{a6}B|");
    }

    /// Text without a `|` goes out unchanged.
    #[test]
    fn plain_text_is_joined_unchanged() {
        assert_eq!(
            payload("Device Online", "cpuminer (rig1) at 10/22/26, 8:00 PM", "").pipe_joined(),
            "Device Online|cpuminer (rig1) at 10/22/26, 8:00 PM|"
        );
    }
}
