// SPDX-License-Identifier: AGPL-3.0-or-later

//! TDP-template state machine + `mining.notify` frame builder.
//!
//! Two halves:
//!
//! - [`SV1TemplateAssembler`] consumes
//!   [`bp_template_distribution::TemplateUpdate`] messages
//!   (`NewTemplate` / `SetNewPrevHash`) and assembles them into a
//!   broadcast-ready [`ActiveSV1Template`]. Returns a [`TemplateChange`]
//!   when the active template flips (NewBlock / Refresh) so callers know
//!   whether to set `clean_jobs=true`.
//!
//! - [`build_notify_frame`] takes an active template, a per-miner
//!   [`bp_mining_job::MiningJob`], a jobId, and the clean-jobs flag, and
//!   emits the line-terminated `mining.notify` bytes. Numeric fields
//!   (version/bits/ntime) are emitted as 8-hex-padded lowercase — a
//!   deliberate ckpool-style choice (see the
//!   `feedback-sv1-notify-hex-padded` memory).
//!
//! The translator is **stateless across calls**: each `apply` mutates the
//! assembler's internal state, each `build_notify_frame` is a pure
//! projection. The Tokio plumbing that drives the assembler from a
//! `TdpHandle::subscribe()` receiver lives in `server.rs` (Task #9).

use std::collections::HashMap;

use bp_mining_job::MiningJob;
use bp_template_distribution::{NewTemplate, SetNewPrevHash, TemplateUpdate};
use serde::Serialize;

// ── Active template ──────────────────────────────────────────────────

/// A fully-assembled template: a NewTemplate paired with its activating
/// SetNewPrevHash, plus pool-side derived fields (network difficulty).
/// One per active block height.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveSV1Template {
    pub template_id: u64,
    pub version: u32,
    /// 32-byte previous-block hash in Bitcoin internal LE order (as
    /// delivered by SV2 TDP). The SV1 wire form swaps each 4-byte word
    /// before hex-encoding — see [`swap_endian_words`].
    pub prev_hash: [u8; 32],
    pub n_bits: u32,
    pub header_timestamp: u32,
    pub network_target: [u8; 32],
    /// f64 approximation of the network difficulty derived from `n_bits`
    /// via the compact-target decoder. Used as a fast pre-filter for
    /// block-found detection (`submissionDifficulty >= networkDifficulty`).
    /// bitcoind is the authoritative validator.
    pub network_difficulty: f64,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_version: u32,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
    /// Pre-encoded hex form of `merkle_path`, computed once per template
    /// activation/refresh. `mining.notify` would otherwise hex-encode the
    /// path on every per-client broadcast — at ~600 clients × ~10
    /// templates/min × ~12 branch entries that's a measurable per-second
    /// allocation rate this cache removes.
    pub merkle_branch_hex: Vec<String>,
}

impl ActiveSV1Template {
    /// Update the active template's coinbase-related fields in place from
    /// a non-future `NewTemplate` arriving for the current prev-hash
    /// (mempool refresh). Other fields (prev_hash, n_bits, header_timestamp,
    /// network_target/difficulty) are left untouched — only a fresh
    /// `SetNewPrevHash` may change them.
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
        self.merkle_branch_hex = encode_merkle_branch(&self.merkle_path);
    }
}

/// Hex-encode each 32-byte merkle-branch entry. Called once per
/// template activation; the result is cached on `ActiveSV1Template`
/// and re-shared across every per-client `mining.notify` build.
fn encode_merkle_branch(path: &[[u8; 32]]) -> Vec<String> {
    path.iter().map(hex::encode).collect()
}

/// Why the active template changed.
///
/// Whether to clear miner jobs: `NewBlock => clean_jobs=true`,
/// `Refresh => clean_jobs=false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateChange {
    /// A `SetNewPrevHash` activated a (possibly previously-cached future)
    /// template. The chain tip has moved — clean_jobs MUST be true so
    /// miners discard work for the old tip.
    NewBlock,
    /// A `NewTemplate(future_template=false)` replaced the coinbase
    /// fields on the existing active template. Same prev-hash, fresh fee
    /// data — clean_jobs is false; miners can keep their queue.
    Refresh,
}

// ── Assembler ────────────────────────────────────────────────────────

/// Combines `NewTemplate` + `SetNewPrevHash` pairs into broadcast-ready
/// `ActiveSV1Template` values.
///
/// The SV2 TDP wire pattern (per
/// `stratum-mining/stratum-apps/.../template_data.rs`):
///
/// - `NewTemplate(future_template=true)` is sent in advance for an
///   upcoming block. The assembler caches it keyed by `template_id`.
/// - `SetNewPrevHash(template_id=X)` arrives when bitcoin-core detects a
///   new tip. The assembler looks up `future_templates[X]`, pairs the two,
///   and produces a [`TemplateChange::NewBlock`] event.
/// - `NewTemplate(future_template=false)` for the *current* tip
///   (fee/mempool refresh) replaces the active template's coinbase fields
///   in place, producing [`TemplateChange::Refresh`].
///
/// Future templates the assembler holds are bounded by the natural cadence
/// (bitcoin-core typically has at most 1–2 cached at once), so we don't
/// LRU-cap the map.
#[derive(Default)]
pub struct SV1TemplateAssembler {
    future_templates: HashMap<u64, NewTemplate>,
    active: Option<ActiveSV1Template>,
}

impl SV1TemplateAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached future templates awaiting activation.
    pub fn future_count(&self) -> usize {
        self.future_templates.len()
    }

    pub fn current(&self) -> Option<&ActiveSV1Template> {
        self.active.as_ref()
    }

    /// Apply one TDP update. Returns the resulting state change, or
    /// `None` if the update was just cached (future template stashed
    /// pending its SetNewPrevHash) or was an outbound-only variant we
    /// don't react to.
    pub fn apply(&mut self, update: &TemplateUpdate) -> Option<TemplateChange> {
        match update {
            TemplateUpdate::NewTemplate(t) => self.apply_new_template(t),
            TemplateUpdate::SetNewPrevHash(p) => self.apply_set_new_prev_hash(p),
            // RequestTransactionData{Success,Error} are responses to
            // explicit RequestTransactionData calls from the pool. They
            // don't affect the broadcastable template state — the
            // pool's block-submission path consumes them separately.
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
        // If there is no active template (out-of-order delivery — should
        // not happen in steady state with bitcoin-core SV2), stash it as
        // if it were a future template; it'll get picked up on the next
        // SetNewPrevHash. This is defensive — production pools rarely see
        // this case because it polls getblocktemplate which always
        // returns a complete state.
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
        // wait for it to arrive. Startup race windows are brief
        // pre-template window where `newMiningJob$` hasn't emitted yet.
        let template = self.future_templates.remove(&p.template_id)?;
        // Any other cached futures are obsolete now — a fresh prev-hash
        // invalidates templates for the previous tip. Clear them so
        // memory stays bounded if bitcoin-core ever spams futures.
        self.future_templates.clear();

        let network_difficulty = network_difficulty_from_n_bits(p.n_bits);
        let merkle_branch_hex = encode_merkle_branch(&template.merkle_path);
        let active = ActiveSV1Template {
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
            merkle_branch_hex,
        };
        self.active = Some(active);
        Some(TemplateChange::NewBlock)
    }
}

impl bp_template_distribution::TemplateAssembler for SV1TemplateAssembler {
    type Change = TemplateChange;
    type Active = ActiveSV1Template;

    fn apply(&mut self, update: &TemplateUpdate) -> Option<Self::Change> {
        SV1TemplateAssembler::apply(self, update)
    }

    fn current(&self) -> Option<&Self::Active> {
        SV1TemplateAssembler::current(self)
    }
}

// ── Pure helpers ─────────────────────────────────────────────────────

/// Swap each 4-byte word inside a 32-byte buffer. Used to convert the
/// Bitcoin internal LE prev-hash form (as delivered by SV2 TDP) to the
/// SV1 `mining.notify`-on-wire form (per ckpool / Stratum-V1 convention).
///
/// Operates on 8 little-endian u32 words: `[w0,w1,…,w7]` →
/// `[swap_u32(w0), swap_u32(w1), …]` where `swap_u32` reverses the
/// 4 bytes of each word.
pub fn swap_endian_words(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        let base = i * 4;
        out[base] = bytes[base + 3];
        out[base + 1] = bytes[base + 2];
        out[base + 2] = bytes[base + 1];
        out[base + 3] = bytes[base];
    }
    out
}

/// Compute approximate network difficulty from compact `n_bits`. Mirrors
/// Network difficulty calculation — f64 arithmetic, max-target floor at
/// `2^208 * 65535`. Loses precision for very low / very high difficulties
/// but matches the existing block-found pre-filter byte-for-byte.
pub fn network_difficulty_from_n_bits(n_bits: u32) -> f64 {
    let mantissa = (n_bits & 0x007f_ffff) as f64;
    let exponent = ((n_bits >> 24) & 0xff) as i32;
    let target = mantissa * 256_f64.powi(exponent - 3);
    let max_target = 2_f64.powi(208) * 65535_f64;
    max_target / target
}

// ── mining.notify frame builder ──────────────────────────────────────

#[derive(Serialize)]
struct MiningNotifyFrame<'a> {
    id: (),
    method: &'a str,
    params: MiningNotifyParams<'a>,
}

/// 9-element tuple — serializes as a JSON array, field order pinned by
/// declaration order. The merkle-branch slot is borrowed from the
/// cached `ActiveSV1Template::merkle_branch_hex` so per-client builds
/// don't re-hex-encode or re-allocate the branch vector.
type MiningNotifyParams<'a> = (
    &'a str,      // jobId
    String,       // prevHash (word-swapped + hex)
    String,       // coinb1 hex
    String,       // coinb2 hex
    &'a [String], // merkle branch (each entry 64-hex chars)
    String,       // version (8-hex padded)
    String,       // nbits (8-hex padded)
    String,       // ntime (8-hex padded)
    bool,         // clean_jobs
);

/// Emit a line-terminated `mining.notify` frame for the given active
/// template + per-miner mining job.
///
/// `job_id_hex` is the lowercase hex string the pool advertises to the
/// miner; it's the same id miners echo back in `mining.submit[1]`.
///
/// Numeric fields version / n_bits / header_timestamp are emitted as
/// **8-hex-padded lowercase** (ckpool convention, see
/// `feedback-sv1-notify-hex-padded` memory). This differs from the old
/// unpadded `Number.toString(16)` — the chosen form because it's
/// observably interchangeable with every real miner and easier to
/// reason about in pcaps/logs.
pub fn build_notify_frame(
    state: &ActiveSV1Template,
    job: &MiningJob,
    job_id_hex: &str,
    clean_jobs: bool,
) -> Vec<u8> {
    let prev_hash_swapped = swap_endian_words(&state.prev_hash);

    let params: MiningNotifyParams = (
        job_id_hex,
        hex::encode(prev_hash_swapped),
        hex::encode(job.coinbase_prefix()),
        hex::encode(job.coinbase_suffix()),
        state.merkle_branch_hex.as_slice(),
        format!("{:08x}", state.version),
        format!("{:08x}", state.n_bits),
        format!("{:08x}", state.header_timestamp),
        clean_jobs,
    );
    let frame = MiningNotifyFrame {
        id: (),
        method: "mining.notify",
        params,
    };
    let mut bytes = serde_json::to_vec(&frame).expect("mining.notify shape is always valid JSON");
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bp_mining_job::{
        build_mining_job_from_tdp, PayoutEntry, TdpCoinbaseTemplate, EXTRANONCE_SLOT_LEN,
    };

    // ── swap_endian_words ─────────────────────────────────────────────

    #[test]
    fn swap_endian_words_reverses_each_four_byte_word() {
        let mut input = [0u8; 32];
        for (i, b) in input.iter_mut().enumerate() {
            *b = i as u8;
        }
        let out = swap_endian_words(&input);
        // word 0: bytes [0,1,2,3] → [3,2,1,0]
        assert_eq!(&out[0..4], &[3, 2, 1, 0]);
        // word 1: bytes [4,5,6,7] → [7,6,5,4]
        assert_eq!(&out[4..8], &[7, 6, 5, 4]);
        // word 7: bytes [28..32] = [28,29,30,31] → [31,30,29,28]
        assert_eq!(&out[28..32], &[31, 30, 29, 28]);
    }

    #[test]
    fn swap_endian_words_is_an_involution() {
        // Applying the swap twice returns the original buffer.
        let mut input = [0u8; 32];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let once = swap_endian_words(&input);
        let twice = swap_endian_words(&once);
        assert_eq!(twice, input);
    }

    #[test]
    fn swap_endian_words_zero_buffer_stays_zero() {
        assert_eq!(swap_endian_words(&[0u8; 32]), [0u8; 32]);
    }

    // ── network_difficulty_from_n_bits ────────────────────────────────

    #[test]
    fn network_difficulty_genesis_is_one() {
        // Genesis nBits 0x1d00ffff → exactly difficulty 1.
        // mantissa = 0xffff, exponent = 0x1d, target = 0xffff * 256^26
        //                                            = 0xffff * 2^208.
        // max_target / target = 1.0.
        let d = network_difficulty_from_n_bits(0x1d00_ffff);
        assert!((d - 1.0).abs() < 1.0e-12, "got difficulty {}", d);
    }

    #[test]
    fn network_difficulty_higher_n_bits_scales_inversely() {
        // 0x1b0404cb is an older real-world bits with diff ~16307.
        let d = network_difficulty_from_n_bits(0x1b0404cb);
        // Loose bound: well above 1, finite, positive.
        assert!(d > 1000.0 && d < 1.0e9, "got difficulty {}", d);
    }

    // ── SV1TemplateAssembler ──────────────────────────────────────────

    fn dummy_new_template(id: u64, future: bool) -> NewTemplate {
        NewTemplate {
            template_id: id,
            future_template: future,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03], // BIP-34 push h=200_000ish
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                // Witness-commit OP_RETURN TxOut: value=0, scriptlen=0x26, script
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value 0
                0x26, // scriptlen 38
                0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, // OP_RETURN OP_PUSH36 magic
            ]
            .into_iter()
            .chain(std::iter::repeat_n(0xCC, 32)) // 32-byte witness commit
            .collect(),
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32], [0x22; 32]],
        }
    }

    fn dummy_prev_hash(template_id: u64, n_bits: u32) -> SetNewPrevHash {
        SetNewPrevHash {
            template_id,
            prev_hash: [0xAB; 32],
            header_timestamp: 0x65a1_b2c3,
            n_bits,
            target: [0xFF; 32],
        }
    }

    #[test]
    fn assembler_starts_empty() {
        let asm = SV1TemplateAssembler::new();
        assert!(asm.current().is_none());
        assert_eq!(asm.future_count(), 0);
    }

    #[test]
    fn future_template_is_cached_until_set_new_prev_hash() {
        let mut asm = SV1TemplateAssembler::new();
        let ev = asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(1, true)));
        assert_eq!(ev, None);
        assert!(asm.current().is_none());
        assert_eq!(asm.future_count(), 1);
    }

    #[test]
    fn set_new_prev_hash_activates_matching_future_template() {
        let mut asm = SV1TemplateAssembler::new();
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(1, true)));
        let ev = asm.apply(&TemplateUpdate::SetNewPrevHash(dummy_prev_hash(
            1,
            0x1d00_ffff,
        )));
        assert_eq!(ev, Some(TemplateChange::NewBlock));
        let active = asm.current().expect("must be active");
        assert_eq!(active.template_id, 1);
        assert_eq!(active.version, 0x2000_0000);
        assert_eq!(active.prev_hash, [0xAB; 32]);
        assert_eq!(active.n_bits, 0x1d00_ffff);
        assert_eq!(active.header_timestamp, 0x65a1_b2c3);
        assert_eq!(active.network_target, [0xFF; 32]);
        assert!((active.network_difficulty - 1.0).abs() < 1.0e-9);
        // future map cleared after activation
        assert_eq!(asm.future_count(), 0);
    }

    #[test]
    fn set_new_prev_hash_without_matching_template_is_a_noop() {
        let mut asm = SV1TemplateAssembler::new();
        let ev = asm.apply(&TemplateUpdate::SetNewPrevHash(dummy_prev_hash(
            99,
            0x1d00_ffff,
        )));
        assert_eq!(ev, None);
        assert!(asm.current().is_none());
    }

    #[test]
    fn non_future_template_refreshes_coinbase_in_place() {
        let mut asm = SV1TemplateAssembler::new();
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(1, true)));
        asm.apply(&TemplateUpdate::SetNewPrevHash(dummy_prev_hash(
            1,
            0x1d00_ffff,
        )));
        let prev_hash_before = asm.current().unwrap().prev_hash;
        let timestamp_before = asm.current().unwrap().header_timestamp;

        // Fee refresh: new id but future=false → replaces coinbase, keeps
        // prev_hash + header_timestamp + n_bits.
        let mut refresh = dummy_new_template(2, false);
        refresh.coinbase_tx_value_remaining = 5_100_000_000; // fees bumped
        let ev = asm.apply(&TemplateUpdate::NewTemplate(refresh));
        assert_eq!(ev, Some(TemplateChange::Refresh));

        let active = asm.current().unwrap();
        assert_eq!(active.template_id, 2);
        assert_eq!(active.coinbase_tx_value_remaining, 5_100_000_000);
        // prev_hash/header_timestamp/n_bits untouched.
        assert_eq!(active.prev_hash, prev_hash_before);
        assert_eq!(active.header_timestamp, timestamp_before);
        assert_eq!(active.n_bits, 0x1d00_ffff);
    }

    #[test]
    fn second_new_block_clears_stale_future_templates() {
        let mut asm = SV1TemplateAssembler::new();
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(1, true)));
        asm.apply(&TemplateUpdate::SetNewPrevHash(dummy_prev_hash(
            1,
            0x1d00_ffff,
        )));

        // Now an extra future arrives but never gets a SetNewPrevHash —
        // when a fresh new-block lands for template 3, both the unused
        // future-1 (already consumed) and future-2 (orphaned) should be
        // gone.
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(2, true)));
        assert_eq!(asm.future_count(), 1);

        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(3, true)));
        assert_eq!(asm.future_count(), 2);

        asm.apply(&TemplateUpdate::SetNewPrevHash(dummy_prev_hash(
            3,
            0x1d00_ffff,
        )));
        assert_eq!(asm.future_count(), 0);
        assert_eq!(asm.current().unwrap().template_id, 3);
    }

    #[test]
    fn request_tx_data_variants_are_ignored_by_the_assembler() {
        let mut asm = SV1TemplateAssembler::new();
        let ev = asm.apply(&TemplateUpdate::RequestTransactionDataError(
            bp_template_distribution::RequestTransactionDataError {
                template_id: 1,
                error_code: "stale-template-id".to_string(),
            },
        ));
        assert_eq!(ev, None);
    }

    // ── build_notify_frame ────────────────────────────────────────────

    fn assembled_active() -> ActiveSV1Template {
        // Fully-deterministic active template — used by frame-build tests.
        ActiveSV1Template {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: {
                // Distinct bytes per word so swap_endian_words can be
                // verified by inspection.
                let mut h = [0u8; 32];
                for (i, b) in h.iter_mut().enumerate() {
                    *b = i as u8;
                }
                h
            },
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
            network_target: [0xFF; 32],
            network_difficulty: 1.0,
            coinbase_prefix: vec![0x03, 0x40, 0x0d, 0x03],
            coinbase_tx_version: 2,
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 5_000_000_000,
            coinbase_tx_outputs: {
                let mut v = vec![0u8; 8];
                v.push(0x26);
                v.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
                v.extend(std::iter::repeat_n(0xCC, 32));
                v
            },
            coinbase_tx_outputs_count: 1,
            coinbase_tx_locktime: 0,
            merkle_path: vec![[0x11; 32], [0x22; 32]],
            merkle_branch_hex: vec![
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
                "2222222222222222222222222222222222222222222222222222222222222222".into(),
            ],
        }
    }

    fn job_from_active(active: &ActiveSV1Template) -> MiningJob {
        let template = TdpCoinbaseTemplate {
            coinbase_prefix: &active.coinbase_prefix,
            coinbase_tx_version: active.coinbase_tx_version,
            coinbase_tx_input_sequence: active.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: active.coinbase_tx_value_remaining,
            coinbase_tx_outputs: &active.coinbase_tx_outputs,
            coinbase_tx_outputs_count: active.coinbase_tx_outputs_count,
            coinbase_tx_locktime: active.coinbase_tx_locktime,
        };
        let payouts = vec![PayoutEntry {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            percent: 100.0,
        }];
        build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
        )
        .unwrap()
    }

    #[test]
    fn build_notify_frame_emits_expected_field_shape() {
        let active = assembled_active();
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "abc", false);
        let s = std::str::from_utf8(&bytes).unwrap();

        // Trailing newline.
        assert!(s.ends_with('\n'));

        // Parse back as a generic value and assert the params shape.
        let parsed: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert!(parsed.get("id").unwrap().is_null());
        assert_eq!(
            parsed.get("method").unwrap().as_str().unwrap(),
            "mining.notify"
        );
        let params = parsed.get("params").unwrap().as_array().unwrap();
        assert_eq!(params.len(), 9);

        // params[0] = jobId
        assert_eq!(params[0].as_str().unwrap(), "abc");

        // params[1] = prev_hash word-swapped
        let expected_swapped = swap_endian_words(&active.prev_hash);
        assert_eq!(params[1].as_str().unwrap(), hex::encode(expected_swapped));

        // params[2] = coinb1, params[3] = coinb2 — match the job's split.
        assert_eq!(
            params[2].as_str().unwrap(),
            hex::encode(job.coinbase_prefix())
        );
        assert_eq!(
            params[3].as_str().unwrap(),
            hex::encode(job.coinbase_suffix())
        );

        // params[4] = merkle_branch
        let branch = params[4].as_array().unwrap();
        assert_eq!(branch.len(), 2);
        assert_eq!(branch[0].as_str().unwrap(), &"11".repeat(32));
        assert_eq!(branch[1].as_str().unwrap(), &"22".repeat(32));

        // params[5..8] = 8-hex-padded version/bits/ntime (ckpool form,
        // per the feedback-sv1-notify-hex-padded memory).
        assert_eq!(params[5].as_str().unwrap(), "20000000");
        assert_eq!(params[6].as_str().unwrap(), "1d00ffff");
        assert_eq!(params[7].as_str().unwrap(), "65a1b2c3");

        // params[8] = clean_jobs
        assert!(!params[8].as_bool().unwrap());
    }

    #[test]
    fn build_notify_frame_clean_jobs_true() {
        let active = assembled_active();
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", true);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        assert!(parsed.get("params").unwrap().as_array().unwrap()[8]
            .as_bool()
            .unwrap());
    }

    #[test]
    fn build_notify_frame_pads_short_numeric_fields() {
        // Version 2, n_bits 0x0000_00ff, ntime 0x10 — all small enough
        // that unpadded hex would be < 8 chars. Padded form must be
        // exactly 8 chars.
        let mut active = assembled_active();
        active.version = 2;
        active.n_bits = 0x0000_00ff;
        active.header_timestamp = 0x10;
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", false);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let params = parsed.get("params").unwrap().as_array().unwrap();
        assert_eq!(params[5].as_str().unwrap(), "00000002");
        assert_eq!(params[6].as_str().unwrap(), "000000ff");
        assert_eq!(params[7].as_str().unwrap(), "00000010");
    }

    #[test]
    fn build_notify_frame_field_order_is_id_method_params() {
        // Pin the field order at the byte level. JSON serialization order
        // `{id, method, params}` emits `id` first, then `method`, then
        // `params`. Our Serialize-derived struct must do the same.
        let active = assembled_active();
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", false);
        let s = std::str::from_utf8(&bytes).unwrap();
        // The first two keys after `{`.
        assert!(s.starts_with("{\"id\":null,\"method\":\"mining.notify\",\"params\":["));
    }

    #[test]
    fn build_notify_frame_empty_merkle_branch_is_an_empty_array() {
        // A template with no other transactions (rare in mainnet, common
        // on a fresh regtest tip) emits an empty merkle_branch — must
        // serialize as `[]`, not omit the field.
        let mut active = assembled_active();
        active.merkle_path = vec![];
        active.merkle_branch_hex = vec![];
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", false);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let branch = parsed.get("params").unwrap().as_array().unwrap()[4]
            .as_array()
            .unwrap();
        assert_eq!(branch.len(), 0);
    }

    #[test]
    fn build_notify_frame_coinb1_coinb2_match_extranonce_splice() {
        // Round-trip: rebuild the full coinbase from coinb1 + 12-byte zero
        // slot + coinb2, decode via rust-bitcoin to ensure the SV1 frame
        // points to a real, valid coinbase tx.
        let active = assembled_active();
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", false);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let params = parsed.get("params").unwrap().as_array().unwrap();
        let coinb1 = hex::decode(params[2].as_str().unwrap()).unwrap();
        let coinb2 = hex::decode(params[3].as_str().unwrap()).unwrap();

        let mut full = Vec::new();
        full.extend_from_slice(&coinb1);
        full.extend_from_slice(&[0u8; EXTRANONCE_SLOT_LEN]);
        full.extend_from_slice(&coinb2);

        use bitcoin::consensus::Decodable;
        bitcoin::Transaction::consensus_decode(&mut full.as_slice())
            .expect("coinb1+slot+coinb2 must decode as a valid bitcoin transaction");
    }
}
