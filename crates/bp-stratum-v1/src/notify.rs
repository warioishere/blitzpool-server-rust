// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`ActiveSV1Template`] (the shared [`ActiveTemplate`] plus the hex every
//! `mining.notify` carries, encoded once per template) and
//! [`build_notify_frame`]. Templates are assembled by the SV2-shared
//! [`bp_template_distribution::TemplateAssembler`].

use std::ops::Deref;

use bp_mining_job::MiningJob;
use bp_template_distribution::{ActiveFromTemplate, ActiveTemplate, NewTemplate, SetNewPrevHash};
use serde::Serialize;

// ── Active template ──────────────────────────────────────────────────

/// The shared [`ActiveTemplate`] plus the hex SV1 sends on every
/// `mining.notify`. Reads of the template fields go through `Deref`;
/// there is deliberately no `DerefMut`, so a source field cannot change
/// without its cached hex being re-derived.
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveSV1Template {
    pub template: ActiveTemplate,
    /// Hex of `merkle_path`, encoded once per activation/refresh instead of
    /// once per connection.
    pub merkle_branch_hex: Vec<String>,
    /// Hex of the header fields every connection shares (prev_hash
    /// word-swapped, version, n_bits, header_timestamp). Kept in sync by
    /// `recompute_notify_header_hex` and `refresh`.
    pub prev_hash_hex: String,
    pub version_hex: String,
    pub n_bits_hex: String,
    pub header_timestamp_hex: String,
}

impl Deref for ActiveSV1Template {
    type Target = ActiveTemplate;

    fn deref(&self) -> &ActiveTemplate {
        &self.template
    }
}

impl ActiveSV1Template {
    /// Wrap `template` with every cache derived from it.
    pub fn from_template(template: ActiveTemplate) -> Self {
        let mut active = Self {
            merkle_branch_hex: encode_merkle_branch(&template.merkle_path),
            template,
            prev_hash_hex: String::new(),
            version_hex: String::new(),
            n_bits_hex: String::new(),
            header_timestamp_hex: String::new(),
        };
        active.recompute_notify_header_hex();
        active
    }

    /// Re-derive the cached header hex. `pub(crate)` so test fixtures that
    /// mutate `template` can re-sync it; the debug guard in
    /// [`build_notify_frame`] catches a forgotten call.
    pub(crate) fn recompute_notify_header_hex(&mut self) {
        self.prev_hash_hex = hex::encode(swap_endian_words(&self.template.prev_hash));
        self.version_hex = format!("{:08x}", self.template.version);
        self.n_bits_hex = format!("{:08x}", self.template.n_bits);
        self.header_timestamp_hex = format!("{:08x}", self.template.header_timestamp);
    }
}

impl ActiveFromTemplate for ActiveSV1Template {
    fn activate(template: NewTemplate, prev: &SetNewPrevHash) -> Self {
        Self::from_template(ActiveTemplate::activate(template, prev))
    }

    fn refresh(&mut self, t: &NewTemplate) {
        self.template.refresh(t);
        self.merkle_branch_hex = encode_merkle_branch(&self.template.merkle_path);
        // Of the four header-hex sources a refresh changes only `version`;
        // the debug guard in `build_notify_frame` checks the other three.
        self.version_hex = format!("{:08x}", self.template.version);
    }
}

fn encode_merkle_branch(path: &[[u8; 32]]) -> Vec<String> {
    path.iter().map(hex::encode).collect()
}

// ── Pure helpers ─────────────────────────────────────────────────────

/// Reverse the bytes of each 4-byte word: converts the internal LE
/// prev-hash from TDP into the form SV1 `mining.notify` puts on the wire.
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

// ── mining.notify frame builder ──────────────────────────────────────

#[derive(Serialize)]
struct MiningNotifyFrame<'a> {
    id: (),
    method: &'a str,
    params: MiningNotifyParams<'a>,
}

/// Serializes as the JSON params array, order pinned by the tuple; every
/// slot borrows a cached hex string so per-client builds do not re-encode.
type MiningNotifyParams<'a> = (
    &'a str,      // jobId
    &'a str,      // prevHash (word-swapped + hex) — cached on the template
    &'a str,      // coinb1 hex — cached on the shared MiningJob
    &'a str,      // coinb2 hex — cached on the shared MiningJob
    &'a [String], // merkle branch (each entry 64-hex chars)
    &'a str,      // version (8-hex padded) — cached
    &'a str,      // nbits (8-hex padded) — cached
    &'a str,      // ntime (8-hex padded) — cached
    bool,         // clean_jobs
);

/// Emit a line-terminated `mining.notify` frame. `job_id_hex` is what the
/// miner echoes back in `mining.submit[1]`; version / n_bits / ntime go out
/// as 8-digit lowercase hex, which every miner accepts.
pub fn build_notify_frame(
    state: &ActiveSV1Template,
    job: &MiningJob,
    job_id_hex: &str,
    clean_jobs: bool,
) -> Vec<u8> {
    // Debug-only stale-cache guard: a desynced `*_hex` fails every test here
    // instead of broadcasting a notify with wrong header/coinbase values.
    debug_assert_eq!(
        state.prev_hash_hex,
        hex::encode(swap_endian_words(&state.prev_hash)),
        "stale prev_hash_hex cache"
    );
    debug_assert_eq!(
        state.version_hex,
        format!("{:08x}", state.version),
        "stale version_hex cache"
    );
    debug_assert_eq!(
        state.n_bits_hex,
        format!("{:08x}", state.n_bits),
        "stale n_bits_hex cache"
    );
    debug_assert_eq!(
        state.header_timestamp_hex,
        format!("{:08x}", state.header_timestamp),
        "stale header_timestamp_hex cache"
    );
    debug_assert_eq!(
        job.coinbase_prefix_hex(),
        hex::encode(job.coinbase_prefix()),
        "stale coinbase_prefix_hex cache"
    );
    debug_assert_eq!(
        job.coinbase_suffix_hex(),
        hex::encode(job.coinbase_suffix()),
        "stale coinbase_suffix_hex cache"
    );

    let params: MiningNotifyParams = (
        job_id_hex,
        state.prev_hash_hex.as_str(),
        job.coinbase_prefix_hex(),
        job.coinbase_suffix_hex(),
        state.merkle_branch_hex.as_slice(),
        state.version_hex.as_str(),
        state.n_bits_hex.as_str(),
        state.header_timestamp_hex.as_str(),
        clean_jobs,
    );
    let frame = MiningNotifyFrame {
        id: (),
        method: "mining.notify",
        params,
    };
    // Upper-bound size so the returned Vec is the builder's only allocation.
    // 64 covers the fixed JSON scaffolding; each string field adds its length
    // + 3 for two quotes and a comma.
    let est = 64
        + job_id_hex.len()
        + 3
        + state.prev_hash_hex.len()
        + 3
        + job.coinbase_prefix_hex().len()
        + 3
        + job.coinbase_suffix_hex().len()
        + 3
        + state.version_hex.len()
        + 3
        + state.n_bits_hex.len()
        + 3
        + state.header_timestamp_hex.len()
        + 3
        + 2 // the merkle branch's own `[` `]`
        + state
            .merkle_branch_hex
            .iter()
            .map(|h| h.len() + 3)
            .sum::<usize>()
        + 6 // "false," — the widest clean_jobs rendering
        + 1; // trailing '\n'
    let mut bytes = Vec::with_capacity(est);
    serde_json::to_writer(&mut bytes, &frame).expect("mining.notify shape is always valid JSON");
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
    use bp_template_distribution::{TemplateAssembler, TemplateUpdate};

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

    // ── Template fixtures ─────────────────────────────────────────────

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

    // ── build_notify_frame ────────────────────────────────────────────

    fn assembled_active() -> ActiveSV1Template {
        // Fully-deterministic active template — used by frame-build tests.
        ActiveSV1Template::from_template(bp_template_distribution::ActiveTemplate {
            template_id: 1,
            version: 0x2000_0000,
            prev_hash: {
                let mut h = [0u8; 32];
                for (i, b) in h.iter_mut().enumerate() {
                    *b = i as u8;
                }
                h
            },
            n_bits: 0x1d00_ffff,
            header_timestamp: 0x65a1_b2c3,
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
        })
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
            sats: 5_000_000_000,
        }];
        build_mining_job_from_tdp(
            Network::Bitcoin,
            &payouts,
            &template,
            "Blitzpool",
            EXTRANONCE_SLOT_LEN,
            [0u8; 32],
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

        // params[5..8] = 8-hex-padded version/bits/ntime (ckpool form).
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
        let mut active = assembled_active();
        active.template.version = 2;
        active.template.n_bits = 0x0000_00ff;
        active.template.header_timestamp = 0x10;
        active.recompute_notify_header_hex();
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", false);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let params = parsed.get("params").unwrap().as_array().unwrap();
        assert_eq!(params[5].as_str().unwrap(), "00000002");
        assert_eq!(params[6].as_str().unwrap(), "000000ff");
        assert_eq!(params[7].as_str().unwrap(), "00000010");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "stale version_hex")]
    fn build_notify_frame_debug_guard_rejects_stale_header_hex() {
        // Mutate a source field without re-syncing the cache.
        let mut active = assembled_active();
        active.template.version = 0x1234_5678; // version_hex now stale
        let job = job_from_active(&active);
        let _ = build_notify_frame(&active, &job, "1", false);
    }

    #[test]
    fn new_block_notify_carries_new_prev_hash_not_stale_cache() {
        // Through the real assembler: each new block's notify carries its own
        // prev_hash, never the previous template's cached hex.
        let notify_prevhash = |asm: &TemplateAssembler<ActiveSV1Template>| -> String {
            let active = asm.current().expect("active template");
            let job = job_from_active(active);
            let bytes = build_notify_frame(active, &job, "1", true);
            let v: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            v["params"].as_array().unwrap()[1]
                .as_str()
                .unwrap()
                .to_string()
        };

        // Block A — prev_hash 0xAA.
        let mut asm = TemplateAssembler::<ActiveSV1Template>::new();
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(1, true)));
        let mut snph_a = dummy_prev_hash(1, 0x1d00_ffff);
        snph_a.prev_hash = [0xAA; 32];
        asm.apply(&TemplateUpdate::SetNewPrevHash(snph_a));
        let notify_a = notify_prevhash(&asm);
        assert_eq!(notify_a, hex::encode(swap_endian_words(&[0xAA; 32])));

        // Block B — a genuinely new tip, prev_hash 0xBB.
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(2, true)));
        let mut snph_b = dummy_prev_hash(2, 0x1d00_ffff);
        snph_b.prev_hash = [0xBB; 32];
        asm.apply(&TemplateUpdate::SetNewPrevHash(snph_b));
        let notify_b = notify_prevhash(&asm);
        assert_eq!(notify_b, hex::encode(swap_endian_words(&[0xBB; 32])));

        // The second notify must NOT carry the first block's prev_hash.
        assert_ne!(notify_a, notify_b, "new block served a stale prev_hash");
    }

    /// After a refresh the notify carries the new merkle branch and version;
    /// the debug guard does not cover the branch, so this test does.
    #[test]
    fn refresh_notify_carries_the_refreshed_merkle_branch_and_version() {
        let mut asm = TemplateAssembler::<ActiveSV1Template>::new();
        asm.apply(&TemplateUpdate::NewTemplate(dummy_new_template(1, true)));
        asm.apply(&TemplateUpdate::SetNewPrevHash(dummy_prev_hash(
            1,
            0x1d00_ffff,
        )));

        let mut refresh = dummy_new_template(2, false);
        refresh.merkle_path = vec![[0x77; 32]];
        refresh.version = 0x2000_0004;
        asm.apply(&TemplateUpdate::NewTemplate(refresh));

        let active = asm.current().expect("active template");
        let job = job_from_active(active);
        let bytes = build_notify_frame(active, &job, "1", false);
        let v: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let params = v["params"].as_array().unwrap();
        assert_eq!(params[4], serde_json::json!([hex::encode([0x77u8; 32])]));
        assert_eq!(params[5].as_str().unwrap(), "20000004");
    }

    #[test]
    fn build_notify_frame_field_order_is_id_method_params() {
        let active = assembled_active();
        let job = job_from_active(&active);
        let bytes = build_notify_frame(&active, &job, "1", false);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("{\"id\":null,\"method\":\"mining.notify\",\"params\":["));
    }

    #[test]
    fn build_notify_frame_empty_merkle_branch_is_an_empty_array() {
        // A template without transactions must serialize `[]`, not omit it.
        let mut active = assembled_active();
        active.template.merkle_path = vec![];
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
        // coinb1 + zeroed extranonce slot + coinb2 must decode as a real tx.
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
