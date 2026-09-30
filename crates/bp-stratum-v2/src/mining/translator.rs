// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the SV2 translator task broadcasts to its per-connection tasks.
//!
//! The template state machine that produces it is shared with SV1 and
//! lives in [`bp_template_distribution::TemplateAssembler`]; SV2 mines on
//! the plain [`ActiveTemplate`], with nothing derived on top.
//!
//! **What the translator does NOT do**: it does NOT build per-channel
//! `NewMiningJob` / `NewExtendedMiningJob` frames. Those are per-channel: a
//! Standard channel needs its own merkle root (built from the channel's
//! `extranonce_prefix` zero-filled into the coinbase slot); an Extended
//! channel needs the coinbase prefix/suffix split at the channel's
//! extranonce-prefix boundary plus the merkle path so the miner can walk it
//! themselves. Per-channel work happens in `mining/client.rs` on top of the
//! broadcast event this module defines.

use std::sync::Arc;

use bp_template_distribution::{ActiveTemplate, TemplateChange};

// ── Broadcast payload ────────────────────────────────────────────────

/// Single broadcast event from the translator to per-connection tasks.
/// The template rides in an `Arc`: the `tokio::sync::broadcast::Sender`
/// clones the payload once per subscriber, so this is N refcount bumps per
/// block change instead of N deep copies of the template.
#[derive(Clone, Debug)]
pub struct TemplateBroadcast {
    pub template: Arc<ActiveTemplate>,
    pub change: TemplateChange,
}
