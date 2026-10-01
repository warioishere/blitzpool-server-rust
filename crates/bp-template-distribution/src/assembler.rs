// SPDX-License-Identifier: AGPL-3.0-or-later

//! The TDP template state machine, shared by the SV1 and SV2 servers: a
//! future `NewTemplate` is cached until its `SetNewPrevHash` activates it, a
//! non-future one refreshes the active template in place. What a protocol
//! derives on top is its own [`ActiveFromTemplate`]; the pairing exists only here.

use std::collections::HashMap;

use crate::message::{NewTemplate, SetNewPrevHash, TemplateSnapshot, TemplateUpdate};

/// Why the active template changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateChange {
    /// A `SetNewPrevHash` activated a (possibly previously-cached future)
    /// template. The chain tip has moved: SV1 sends `clean_jobs=true` so
    /// miners discard work for the old tip; SV2 retires every channel's
    /// jobs and sends `SetNewPrevHash` before the new job.
    NewBlock,
    /// A `NewTemplate(future_template=false)` replaced the coinbase fields
    /// on the existing active template. Same prev-hash, fresh fee data:
    /// SV1 sends `clean_jobs=false`, SV2 sends a fresh job without a
    /// retire cycle.
    Refresh,
}

/// A `NewTemplate` joined with its activating `SetNewPrevHash`. `prev_hash`
/// stays in Bitcoin internal LE order, as bitcoin-core and SV2 carry it; SV1
/// word-swaps it for `mining.notify`.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveTemplate {
    pub template_id: u64,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    pub header_timestamp: u32,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_version: u32,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
}

/// What a protocol builds from a paired template. The assembler calls
/// [`activate`](Self::activate) on a new tip and [`refresh`](Self::refresh)
/// on a fee refresh; both must keep every derived field in sync with the
/// fields they change.
pub trait ActiveFromTemplate: Clone {
    fn activate(template: NewTemplate, prev: &SetNewPrevHash) -> Self;
    fn refresh(&mut self, template: &NewTemplate);
}

impl ActiveFromTemplate for ActiveTemplate {
    fn activate(template: NewTemplate, prev: &SetNewPrevHash) -> Self {
        Self {
            template_id: template.template_id,
            version: template.version,
            prev_hash: prev.prev_hash,
            n_bits: prev.n_bits,
            header_timestamp: prev.header_timestamp,
            coinbase_prefix: template.coinbase_prefix,
            coinbase_tx_version: template.coinbase_tx_version,
            coinbase_tx_input_sequence: template.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: template.coinbase_tx_value_remaining,
            coinbase_tx_outputs: template.coinbase_tx_outputs,
            coinbase_tx_outputs_count: template.coinbase_tx_outputs_count,
            coinbase_tx_locktime: template.coinbase_tx_locktime,
            merkle_path: template.merkle_path,
        }
    }

    /// Only the coinbase / merkle fields move. `prev_hash`, `n_bits` and
    /// `header_timestamp` are left untouched — only a fresh `SetNewPrevHash`
    /// may change them.
    fn refresh(&mut self, t: &NewTemplate) {
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

/// Combines `NewTemplate` + `SetNewPrevHash` pairs into the active template
/// `A`, owned by the translator task that drives a
/// [`crate::TdpHandle::subscribe`] receiver. The future cache is cleared on
/// every pairing, so it stays small.
pub struct TemplateAssembler<A> {
    future_templates: HashMap<u64, NewTemplate>,
    active: Option<A>,
}

impl<A> Default for TemplateAssembler<A> {
    fn default() -> Self {
        Self {
            future_templates: HashMap::new(),
            active: None,
        }
    }
}

impl<A: ActiveFromTemplate> TemplateAssembler<A> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached future templates awaiting activation.
    pub fn future_count(&self) -> usize {
        self.future_templates.len()
    }

    /// The most recently paired template. `None` until the first
    /// `SetNewPrevHash` arrives.
    pub fn current(&self) -> Option<&A> {
        self.active.as_ref()
    }

    /// Apply one TDP update. Returns the resulting change if the active
    /// template flipped, or `None` if the update was only cached or is a
    /// variant that does not affect the template.
    pub fn apply(&mut self, update: &TemplateUpdate) -> Option<TemplateChange> {
        match update {
            TemplateUpdate::NewTemplate(t) => self.apply_new_template(t),
            TemplateUpdate::SetNewPrevHash(p) => self.apply_set_new_prev_hash(p),
            TemplateUpdate::RequestTransactionDataSuccess(_)
            | TemplateUpdate::RequestTransactionDataError(_) => None,
        }
    }

    /// Replay a [`TemplateSnapshot`] so a late subscriber recovers the state
    /// the broadcast missed; `None` unless both halves of the pair apply.
    /// Side effects stay with the caller, since they vary per protocol.
    pub fn bootstrap_from_snapshot(
        &mut self,
        snapshot: TemplateSnapshot,
    ) -> Option<(A, TemplateChange)> {
        if let Some(t) = snapshot.new_template {
            let _ = self.apply(&TemplateUpdate::NewTemplate(t));
        }
        let change = self.apply(&TemplateUpdate::SetNewPrevHash(snapshot.set_new_prev_hash?))?;
        Some((self.current()?.clone(), change))
    }

    fn apply_new_template(&mut self, t: &NewTemplate) -> Option<TemplateChange> {
        if t.future_template {
            // Stash until the matching SetNewPrevHash arrives.
            self.future_templates.insert(t.template_id, t.clone());
            return None;
        }
        // Non-future: a fee/mempool refresh for the current prev-hash. With
        // no active template yet it is stashed like a future one and picked
        // up on the next SetNewPrevHash.
        match self.active.as_mut() {
            Some(active) => {
                active.refresh(t);
                Some(TemplateChange::Refresh)
            }
            None => {
                self.future_templates.insert(t.template_id, t.clone());
                None
            }
        }
    }

    fn apply_set_new_prev_hash(&mut self, p: &SetNewPrevHash) -> Option<TemplateChange> {
        // No matching NewTemplate (out-of-order or first-startup race):
        // nothing to broadcast yet — wait for it to arrive.
        let template = self.future_templates.remove(&p.template_id)?;
        // A fresh prev-hash makes every other cached future obsolete.
        self.future_templates.clear();
        self.active = Some(A::activate(template, p));
        Some(TemplateChange::NewBlock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{RequestTransactionDataError, RequestTransactionDataSuccess};

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

    fn assembler() -> TemplateAssembler<ActiveTemplate> {
        TemplateAssembler::new()
    }

    #[test]
    fn assembler_starts_empty() {
        let a = assembler();
        assert!(a.current().is_none());
        assert_eq!(a.future_count(), 0);
    }

    // ── Future template stashing ────────────────────────────────────

    /// `NewTemplate(future=true)` alone produces no change — it's stashed
    /// pending the matching `SetNewPrevHash`.
    #[test]
    fn future_new_template_is_stashed() {
        let mut a = assembler();
        let out = a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        assert_eq!(out, None);
        assert_eq!(a.future_count(), 1);
        assert!(a.current().is_none());
    }

    /// A second future template stacks alongside the first.
    #[test]
    fn multiple_future_templates_stack() {
        let mut a = assembler();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::NewTemplate(new_template(2, true)));
        assert_eq!(a.future_count(), 2);
    }

    // ── Pairing ─────────────────────────────────────────────────────

    /// future-NewTemplate + matching SetNewPrevHash → `NewBlock`, and
    /// `current()` carries the header fields from the SetNewPrevHash.
    #[test]
    fn future_template_paired_with_set_new_prev_hash_emits_new_block() {
        let mut a = assembler();
        a.apply(&TemplateUpdate::NewTemplate(new_template(7, true)));
        let out = a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            7,
            0x1d00_ffff,
        )));
        assert_eq!(out, Some(TemplateChange::NewBlock));
        let active = a.current().expect("must be active");
        assert_eq!(active.template_id, 7);
        assert_eq!(active.version, 0x2000_0000);
        assert_eq!(active.prev_hash, [0xAB; 32]);
        assert_eq!(active.n_bits, 0x1d00_ffff);
        assert_eq!(active.header_timestamp, 0x6500_0001);
        assert_eq!(a.future_count(), 0, "future cache cleared on activation");
    }

    /// SetNewPrevHash without a matching future template is a no-op
    /// (startup race — wait for the template to arrive).
    #[test]
    fn set_new_prev_hash_without_matching_template_is_a_noop() {
        let mut a = assembler();
        let out = a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            7,
            0x1d00_ffff,
        )));
        assert_eq!(out, None);
        assert!(a.current().is_none());
    }

    /// Activating a new prev_hash clears OTHER cached futures — templates
    /// for the previous tip are obsolete.
    #[test]
    fn activating_clears_obsolete_future_templates() {
        let mut a = assembler();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::NewTemplate(new_template(2, true)));
        a.apply(&TemplateUpdate::NewTemplate(new_template(3, true)));
        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            2,
            0x1d00_ffff,
        )));
        assert_eq!(a.future_count(), 0);
    }

    /// A future that never got its SetNewPrevHash is dropped by the next
    /// block's activation.
    #[test]
    fn second_new_block_clears_stale_future_templates() {
        let mut a = assembler();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            1,
            0x1d00_ffff,
        )));
        a.apply(&TemplateUpdate::NewTemplate(new_template(2, true)));
        assert_eq!(a.future_count(), 1);
        a.apply(&TemplateUpdate::NewTemplate(new_template(3, true)));
        assert_eq!(a.future_count(), 2);

        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            3,
            0x1d00_ffff,
        )));
        assert_eq!(a.future_count(), 0);
        assert_eq!(a.current().unwrap().template_id, 3);
    }

    // ── Refresh ─────────────────────────────────────────────────────

    /// A non-future NewTemplate refreshes coinbase fields but not the header fields.
    #[test]
    fn non_future_new_template_refreshes_coinbase_in_place() {
        let mut a = assembler();
        a.apply(&TemplateUpdate::NewTemplate(new_template(1, true)));
        a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
            1,
            0x1d00_ffff,
        )));
        let before = a.current().unwrap().clone();

        let mut refreshed = new_template(99, false);
        refreshed.coinbase_prefix = vec![0xDE, 0xAD, 0xBE, 0xEF];
        refreshed.coinbase_tx_value_remaining = 4_999_999_000;
        let out = a.apply(&TemplateUpdate::NewTemplate(refreshed));

        assert_eq!(out, Some(TemplateChange::Refresh));
        let active = a.current().unwrap();
        assert_eq!(active.template_id, 99, "template_id swaps on refresh");
        assert_eq!(active.coinbase_prefix, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(active.coinbase_tx_value_remaining, 4_999_999_000);
        assert_eq!(active.prev_hash, before.prev_hash);
        assert_eq!(active.n_bits, before.n_bits);
        assert_eq!(active.header_timestamp, before.header_timestamp);
    }

    /// Non-future NewTemplate with NO active template yet is stashed.
    #[test]
    fn non_future_template_without_active_stashes_as_future() {
        let mut a = assembler();
        let out = a.apply(&TemplateUpdate::NewTemplate(new_template(7, false)));
        assert_eq!(out, None);
        assert_eq!(a.future_count(), 1);
        assert!(a.current().is_none());
    }

    /// Startup → future template → activate → refresh → next block.
    #[test]
    fn full_lifecycle() {
        let mut a = assembler();
        assert_eq!(
            a.apply(&TemplateUpdate::NewTemplate(new_template(1, true))),
            None
        );
        assert_eq!(
            a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
                1,
                0x1d00_ffff,
            ))),
            Some(TemplateChange::NewBlock)
        );
        assert_eq!(
            a.apply(&TemplateUpdate::NewTemplate(new_template(2, false))),
            Some(TemplateChange::Refresh)
        );
        assert_eq!(
            a.apply(&TemplateUpdate::NewTemplate(new_template(3, true))),
            None
        );
        assert_eq!(
            a.apply(&TemplateUpdate::SetNewPrevHash(set_new_prev_hash(
                3,
                0x1d00_ffff,
            ))),
            Some(TemplateChange::NewBlock)
        );
        assert_eq!(a.current().unwrap().template_id, 3);
    }

    /// `RequestTransactionData*` responses don't affect the template state.
    #[test]
    fn request_tx_data_variants_dont_affect_state() {
        let mut a = assembler();
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

    // ── bootstrap_from_snapshot ─────────────────────────────────────

    /// A snapshot holding both halves of a pair replays into the active
    /// template; one missing its SetNewPrevHash yields nothing.
    #[test]
    fn bootstrap_from_snapshot_needs_both_halves() {
        let mut a = assembler();
        let (active, change) = a
            .bootstrap_from_snapshot(TemplateSnapshot {
                new_template: Some(new_template(5, true)),
                set_new_prev_hash: Some(set_new_prev_hash(5, 0x1d00_ffff)),
                last_update_at: None,
            })
            .expect("both halves present");
        assert_eq!(change, TemplateChange::NewBlock);
        assert_eq!(active.template_id, 5);

        let mut a = assembler();
        assert!(a
            .bootstrap_from_snapshot(TemplateSnapshot {
                new_template: Some(new_template(5, true)),
                set_new_prev_hash: None,
                last_update_at: None,
            })
            .is_none());
    }
}
