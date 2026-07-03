// SPDX-License-Identifier: AGPL-3.0-or-later

//! SV2 TDP-translator: pair [`bp_template_distribution::TemplateUpdate`]
//! events (`NewTemplate` + `SetNewPrevHash`) into a broadcast-ready
//! [`ActiveSV2Template`] and emit a [`TemplateChange`] each time the
//! active template flips.
//!
//! **What the translator does NOT do**: it does NOT build per-channel
//! `NewMiningJob` / `NewExtendedMiningJob` frames. Those are
//! per-channel: a Standard channel needs its own merkle root (built
//! from the channel's `extranonce_prefix` zero-filled into the coinbase
//! slot); an Extended channel needs the coinbase prefix/suffix split
//! at the channel's extranonce-prefix boundary plus the merkle path so
//! the miner can walk it themselves. Per-channel work happens in
//! `mining/client.rs` on top of the broadcast event this module emits.
//!
//! Structurally identical to `bp_stratum_v1::notify::SV1TemplateAssembler`
//! — same future-template-caching state-machine, same NewBlock-vs-Refresh
//! classification. The two could in principle share an assembler crate;
//! we defer that decision until both translators land and we can compare
//! the field sets line-by-line. The TDP wire types (`NewTemplate`,
//! `SetNewPrevHash`) come from [`bp_template_distribution`] in both
//! cases.
//!
//! ## Pairing rules (SV2 TDP wire pattern)
//!
//! - `NewTemplate(future_template=true)` is sent in advance for an
//!   upcoming block. The assembler caches it keyed by `template_id`.
//! - `SetNewPrevHash(template_id=X)` arrives when bitcoin-core detects
//!   a new tip. The assembler looks up `future_templates[X]`, pairs the
//!   two, and emits [`TemplateChange::NewBlock`].
//! - `NewTemplate(future_template=false)` for the *current* tip
//!   (fee/mempool refresh) replaces the active template's coinbase
//!   fields in place, emitting [`TemplateChange::Refresh`].
//! - `RequestTransactionDataSuccess` / `Error` are responses to
//!   explicit `RequestTransactionData` calls; the pool's
//!   block-submission path consumes those separately.

use std::collections::HashMap;
use std::sync::Arc;

use bp_share::Difficulty;
use bp_template_distribution::{NewTemplate, SetNewPrevHash, TemplateUpdate};

// ── Active template ──────────────────────────────────────────────────

/// Fully-paired template: a `NewTemplate` joined with its activating
/// `SetNewPrevHash` plus pool-side derived fields (network difficulty).
/// One per active block height.
///
/// `prev_hash` stays in Bitcoin internal LE order — that's the natural
/// form delivered by `bitcoin_core_sv2::BitcoinCoreSv2TDP` AND the form
/// expected by SV2 wire `SetNewPrevHash` (no swap needed unlike SV1's
/// `mining.notify`, which does word-swap on the same field).
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveSV2Template {
    pub template_id: u64,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    pub header_timestamp: u32,
    pub network_target: [u8; 32],
    /// Network difficulty derived from `n_bits` (compact-target decoder).
    /// Used as the block-found pre-filter (`submission_difficulty >=
    /// network_difficulty`). bitcoind is the authoritative validator.
    pub network_difficulty: Difficulty,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_version: u32,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
}

impl ActiveSV2Template {
    /// Update only the coinbase / merkle fields in place from a
    /// non-future `NewTemplate` arriving for the current prev-hash
    /// (mempool refresh). `prev_hash`, `n_bits`, `header_timestamp`,
    /// `network_target` and `network_difficulty` are left untouched —
    /// only a fresh `SetNewPrevHash` may change them.
    fn replace_coinbase_fields(&mut self, t: &NewTemplate) {
        self.template_id = t.template_id;
        self.version = t.version;
        self.coinbase_prefix = t.coinbase_prefix.clone();
        self.coinbase_tx_version = t.coinbase_tx_version;
        self.coinbase_tx_input_sequence = t.coinbase_tx_input_sequence;
        self.coinbase_tx_value_remaining = t.coinbase_tx_value_remaining;
        self.coinbase_tx_outputs = t.coinbase_tx_outputs.clone();
        self.coinbase_tx_outputs_count = t.coinbase_tx_outputs_count;
        self.coinbase_tx_locktime = t.coinbase_tx_locktime;
        self.merkle_path = t.merkle_path.clone();
    }
}

// ── TemplateChange ───────────────────────────────────────────────────

/// Why the active template changed. Drives the per-channel decision
/// whether to send `SetNewPrevHash` first (NewBlock case) and whether
/// to retire the existing extended-jobs map before broadcasting the
/// fresh `NewExtendedMiningJob` (NewBlock yes, Refresh no).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateChange {
    /// A `SetNewPrevHash` activated a (possibly previously-cached
    /// future) template. The chain tip has moved — per-channel
    /// extended-jobs must be retired (sv2-ui#143 retire-not-clear) and
    /// `SetNewPrevHash` must be sent to every channel before the new
    /// `NewExtendedMiningJob`.
    NewBlock,
    /// A `NewTemplate(future_template=false)` replaced the coinbase
    /// fields on the existing active template. Same prev-hash, fresh
    /// fee/mempool data — no retire-cycle, just send a fresh
    /// `NewExtendedMiningJob` to each channel.
    Refresh,
}

// ── Broadcast payload ────────────────────────────────────────────────

/// Single broadcast event from the translator to per-connection tasks.
/// The template rides in an `Arc`: the `tokio::sync::broadcast::Sender`
/// clones the payload once per subscriber, and without the `Arc` every
/// connection would deep-copy the whole template (coinbase prefix/output
/// buffers + merkle path, ~1 KB) on every block change — N refcount
/// bumps instead of N allocations. Field reads deref transparently.
#[derive(Clone, Debug)]
pub struct TemplateBroadcast {
    pub template: Arc<ActiveSV2Template>,
    pub change: TemplateChange,
}

// ── Assembler ────────────────────────────────────────────────────────

/// Combines `NewTemplate` + `SetNewPrevHash` pairs into broadcast-ready
/// `ActiveSV2Template` values.
///
/// Stateful per-thread: owned `&mut` by the translator task that drives
/// the `bp_template_distribution::TdpHandle::subscribe()` receiver.
///
/// Future templates the assembler holds are bounded by the natural
/// cadence (bitcoin-core has at most 1–2 cached at once), and we clear
/// the cache on every successful pairing — so the map size is
/// effectively `O(1)`.
#[derive(Default)]
pub struct SV2TemplateAssembler {
    future_templates: HashMap<u64, NewTemplate>,
    active: Option<ActiveSV2Template>,
}

impl SV2TemplateAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached future templates awaiting activation.
    pub fn future_count(&self) -> usize {
        self.future_templates.len()
    }

    /// Snapshot of the most-recently-paired template. `None` until the
    /// first `SetNewPrevHash` arrives. Used by the I/O layer to seed
    /// newly-accepted connections with the current template without
    /// waiting for the next broadcast.
    pub fn current(&self) -> Option<&ActiveSV2Template> {
        self.active.as_ref()
    }

    /// Apply one TDP update. Returns the resulting [`TemplateChange`]
    /// if the active template flipped, or `None` if the update was
    /// just cached / was an outbound-only variant that doesn't affect
    /// the broadcastable state.
    pub fn apply(&mut self, update: &TemplateUpdate) -> Option<TemplateChange> {
        match update {
            TemplateUpdate::NewTemplate(t) => self.apply_new_template(t),
            TemplateUpdate::SetNewPrevHash(p) => self.apply_set_new_prev_hash(p),
            // RequestTransactionData{Success,Error} are responses to
            // explicit `RequestTransactionData` calls. They don't affect
            // the broadcastable template state — the pool's
            // block-submission path consumes them separately.
            TemplateUpdate::RequestTransactionDataSuccess(_)
            | TemplateUpdate::RequestTransactionDataError(_) => None,
        }
    }

    fn apply_new_template(&mut self, t: &NewTemplate) -> Option<TemplateChange> {
        if t.future_template {
            // Stash until the matching SetNewPrevHash arrives.
            self.future_templates.insert(t.template_id, t.clone());
            return None;
        }
        // Non-future: a fee/mempool refresh for the current prev-hash.
        // Replace the active template's coinbase fields in place.
        // If there is no active template (out-of-order delivery —
        // should not happen in steady state with bitcoin-core SV2),
        // stash it as if it were a future template; it'll get picked
        // up on the next SetNewPrevHash. Defensive — matches what
        // `bp_stratum_v1::notify::SV1TemplateAssembler` does in the
        // same edge case.
        match self.active.as_mut() {
            Some(active) => {
                active.replace_coinbase_fields(t);
                Some(TemplateChange::Refresh)
            }
            None => {
                self.future_templates.insert(t.template_id, t.clone());
                None
            }
        }
    }

    fn apply_set_new_prev_hash(&mut self, p: &SetNewPrevHash) -> Option<TemplateChange> {
        // Look up the matching NewTemplate. If absent (out-of-order or
        // first-startup race), there's nothing we can broadcast yet —
        // wait for it to arrive.
        let template = self.future_templates.remove(&p.template_id)?;
        // Any other cached futures are obsolete now — a fresh
        // prev-hash invalidates templates for the previous tip. Clear
        // them so memory stays bounded if bitcoin-core ever spams
        // futures.
        self.future_templates.clear();

        let network_difficulty = network_difficulty_from_n_bits(p.n_bits);
        let active = ActiveSV2Template {
            template_id: template.template_id,
            version: template.version,
            prev_hash: p.prev_hash,
            n_bits: p.n_bits,
            header_timestamp: p.header_timestamp,
            network_target: p.target,
            network_difficulty,
            coinbase_prefix: template.coinbase_prefix,
            coinbase_tx_version: template.coinbase_tx_version,
            coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
            coinbase_tx_outputs: template.coinbase_tx_outputs,
            coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
            coinbase_tx_locktime: template.coinbase_tx_locktime,
            merkle_path: template.merkle_path,
        };
        self.active = Some(active);
        Some(TemplateChange::NewBlock)
    }
}

impl bp_template_distribution::TemplateAssembler for SV2TemplateAssembler {
    type Change = TemplateChange;
    type Active = ActiveSV2Template;

    fn apply(&mut self, update: &TemplateUpdate) -> Option<Self::Change> {
        SV2TemplateAssembler::apply(self, update)
    }

    fn current(&self) -> Option<&Self::Active> {
        SV2TemplateAssembler::current(self)
    }
}

// ── Pure helpers ─────────────────────────────────────────────────────

/// Approximate network difficulty from compact `n_bits`. Uses f64
/// arithmetic with max-target floor at `2^208 * 65535`. Loses precision
/// for very low / very high difficulties but matches the standard
/// block-found pre-filter calculation.
pub fn network_difficulty_from_n_bits(n_bits: u32) -> Difficulty {
    let mantissa = (n_bits & 0x007f_ffff) as f64;
    let exponent = ((n_bits >> 24) & 0xff) as i32;
    let target = mantissa * 256_f64.powi(exponent - 3);
    let max_target = 2_f64.powi(208) * 65535_f64;
    Difficulty(max_target / target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_template(template_id: u64, future: bool) -> NewTemplate {
        NewTemplate {
            template_id,
            future_template: future,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![0xAA; 16],
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32]],
        }
    }

    fn set_new_prev_hash(template_id: u64, n_bits: u32) -> SetNewPrevHash {
        SetNewPrevHash {
            template_id,
            prev_hash: [0xAB; 32],
            header_timestamp: 0x6500_0001,
            n_bits,
            target: [0xFF; 32],
        }
    }

    // ── Future template stashing ────────────────────────────────────

    /// `NewTemplate(future=true)` alone produces no change — it's
    /// stashed pending the matching `SetNewPrevHash`.
    #[test]
    fn future_new_template_is_stashed() {
        let mut a = SV2TemplateAssembler::new();
        let out = a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        assert_eq!(out, None);
        assert_eq!(a.future_count(), 1);
        assert!(a.current().is_none());
    }

    /// A second future template stacks alongside the first.
    #[test]
    fn multiple_future_templates_stack() {
        let mut a = SV2TemplateAssembler::new();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::NewTemplate(new_template(2, true)));
        assert_eq!(a.future_count(), 2);
    }

    // ── Pairing happy-path ──────────────────────────────────────────

    /// future-NewTemplate + matching SetNewPrevHash → `NewBlock` event +
    /// `current()` returns paired template.
    #[test]
    fn future_template_paired_with_set_new_prev_hash_emits_new_block() {
        let mut a = SV2TemplateAssembler::new();
        a.apply(&TemplateUpdate::NewTemplate(new_template(7, true)));
        let out = a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            7,
            0x1d00_ffff,
        )));
        assert_eq!(out, Some(TemplateChange::NewBlock));
        let active = a.current().expect("must be active");
        assert_eq!(active.template_id, 7);
        assert_eq!(active.n_bits, 0x1d00_ffff);
        assert_eq!(active.prev_hash, [0xAB; 32]);
        // network_difficulty was derived from n_bits.
        assert!(active.network_difficulty.as_f64() > 0.0);
        // Future-template cache cleared on activation.
        assert_eq!(a.future_count(), 0);
    }

    /// SetNewPrevHash without a matching future template returns None
    /// (startup race — wait for the template to arrive).
    #[test]
    fn set_new_prev_hash_without_matching_template_is_a_noop() {
        let mut a = SV2TemplateAssembler::new();
        let out = a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            7,
            0x1d00_ffff,
        )));
        assert_eq!(out, None);
        assert!(a.current().is_none());
    }

    /// Activating a new prev_hash clears OTHER cached futures —
    /// templates for the previous tip are obsolete.
    #[test]
    fn activating_clears_obsolete_future_templates() {
        let mut a = SV2TemplateAssembler::new();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::NewTemplate(new_template(2, true)));
        a.apply(&TemplateUpdate::NewTemplate(new_template(3, true)));
        // Activate template 2.
        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            2,
            0x1d00_ffff,
        )));
        // The other two cached futures are now obsolete.
        assert_eq!(a.future_count(), 0);
    }

    // ── Refresh path ────────────────────────────────────────────────

    /// Non-future NewTemplate for the current tip replaces coinbase
    /// fields in place + emits `Refresh`. prev_hash / n_bits / target
    /// are NOT touched.
    #[test]
    fn non_future_new_template_refreshes_coinbase_in_place() {
        let mut a = SV2TemplateAssembler::new();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            1,
            0x1d00_ffff,
        )));
        let original_prev = a.current().unwrap().prev_hash;
        let original_n_bits = a.current().unwrap().n_bits;

        let mut refreshed = new_template(99, false);
        refreshed.coinbase_prefix = vec![0xDE, 0xAD, 0xBE, 0xEF];
        refreshed.coinbase_tx_value_remaining = 4_999_999_000;
        let out = a.apply(&TemplateUpdate::NewTemplate(refreshed));

        assert_eq!(out, Some(TemplateChange::Refresh));
        let active = a.current().unwrap();
        assert_eq!(active.template_id, 99, "template_id swaps on refresh");
        assert_eq!(
            active.coinbase_prefix,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            "coinbase fields swap on refresh"
        );
        assert_eq!(active.coinbase_tx_value_remaining, 4_999_999_000);
        // prev_hash / n_bits / target untouched.
        assert_eq!(active.prev_hash, original_prev);
        assert_eq!(active.n_bits, original_n_bits);
    }

    /// Non-future NewTemplate with NO active template yet is stashed
    /// (defensive — matches SV1 assembler).
    #[test]
    fn non_future_template_without_active_stashes_as_future() {
        let mut a = SV2TemplateAssembler::new();
        let out = a.apply(&TemplateUpdate::NewTemplate(new_template(7, false)));
        assert_eq!(out, None);
        assert_eq!(a.future_count(), 1);
        assert!(a.current().is_none());
    }

    // ── End-to-end lifecycle ────────────────────────────────────────

    /// Full sequence: startup → future template → activate → refresh
    /// → next block.
    #[test]
    fn full_lifecycle() {
        let mut a = SV2TemplateAssembler::new();
        // 1. Startup-future arrives.
        assert_eq!(
            a.apply(&TemplateUpdate::NewTemplate(new_template(1, true))),
            None
        );
        // 2. SetNewPrevHash activates it.
        assert_eq!(
            a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
                1,
                0x1d00_ffff,
            ))),
            Some(TemplateChange::NewBlock)
        );
        // 3. Fee refresh (non-future, current tip).
        assert_eq!(
            a.apply(&TemplateUpdate::NewTemplate(new_template(2, false))),
            Some(TemplateChange::Refresh)
        );
        // 4. Next-block future arrives.
        assert_eq!(
            a.apply(&TemplateUpdate::NewTemplate(new_template(3, true))),
            None
        );
        // 5. Activating template 3 = NewBlock for the next height.
        assert_eq!(
            a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
                3,
                0x1d00_ffff,
            ))),
            Some(TemplateChange::NewBlock)
        );
        assert_eq!(a.current().unwrap().template_id, 3);
    }

    // ── Outbound-only variants are ignored ──────────────────────────

    /// `RequestTransactionDataSuccess` / `Error` arrive as responses to
    /// explicit pool requests; they don't affect the broadcastable
    /// template state.
    #[test]
    fn request_tx_data_variants_dont_affect_state() {
        use bp_template_distribution::{
            RequestTransactionDataError, RequestTransactionDataSuccess,
        };
        let mut a = SV2TemplateAssembler::new();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            1,
            0x1d00_ffff,
        )));
        let before = a.current().cloned();
        assert_eq!(
            a.apply(&TemplateUpdate::RequestTransactionDataSuccess(
                RequestTransactionDataSuccess {
                    template_id: 1,
                    excess_data: vec![],
                    transaction_list: vec![],
                }
            )),
            None
        );
        assert_eq!(
            a.apply(&TemplateUpdate::RequestTransactionDataError(
                RequestTransactionDataError {
                    template_id: 1,
                    error_code: "tx-data-not-yet-known".to_string(),
                }
            )),
            None
        );
        assert_eq!(a.current().cloned(), before);
    }

    // ── network_difficulty_from_n_bits ─────────────────────────────

    /// Sanity-check the compact-target decoder against the known
    /// `n_bits` for difficulty 1: `0x1d00_ffff` produces ≈ 1.0.
    #[test]
    fn network_difficulty_for_n_bits_diff_one_is_one() {
        let d = network_difficulty_from_n_bits(0x1d00_ffff);
        assert!((d.as_f64() - 1.0).abs() < 1e-6, "expected ≈ 1.0, got {d}");
    }

    /// Higher difficulty (larger exponent shift down) → higher value.
    #[test]
    fn network_difficulty_grows_with_harder_target() {
        let easy = network_difficulty_from_n_bits(0x1d00_ffff); // diff 1
        let hard = network_difficulty_from_n_bits(0x1700_ffff); // mainnet-ish
        assert!(hard.as_f64() > easy.as_f64());
    }
}
