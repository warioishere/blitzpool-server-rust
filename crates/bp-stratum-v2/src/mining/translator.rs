// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the SV2 translator task broadcasts to its per-connection tasks: the
//! plain [`ActiveTemplate`] from the [`bp_template_distribution::TemplateAssembler`]
//! shared with SV1. Job frames are built per channel in `mining/client.rs`,
//! since each depends on the channel's extranonce prefix.

use std::sync::Arc;

use bp_template_distribution::{ActiveTemplate, TemplateChange};

// ── Broadcast payload ────────────────────────────────────────────────

/// One broadcast event. The template rides in an `Arc` because `broadcast`
/// clones the payload once per subscriber.
#[derive(Clone, Debug)]
pub struct TemplateBroadcast {
    pub template: Arc<ActiveTemplate>,
    pub change: TemplateChange,
}
