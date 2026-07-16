// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(unsafe_code)] // dev-only bench: a counting global allocator needs `unsafe impl GlobalAlloc`.
#![allow(clippy::print_stdout)] // dev-only bench: reporting alloc counts to stdout is the point.
//
//! Hot-path micro-benchmark for the SV1 `mining.notify` builder
//! ([`bp_stratum_v1::build_notify_frame`]) — the per-client broadcast run once
//! for every connection on every new job (new block / template refresh).
//!
//! `build_notify_frame` borrows all its hex from caches: the header-constant
//! fields (prev_hash, version, n_bits, header_timestamp) from the template, and
//! the coinbase (coinb1/coinb2) from the shared `MiningJob`. Every one of those
//! is identical for all clients on a template, so re-encoding per client was
//! pure waste. The output frame Vec is additionally pre-sized to an upper
//! bound, so serde_json writes it without a realloc — that Vec is then the
//! builder's only allocation. The bench reports:
//!   - **allocations per build** — asserts the builder is down to a single
//!     alloc, and shows the 6 per-client hex encodings the caches removed.
//!   - **ns/op** (criterion).
//!
//! Run: `cargo bench -p bp-stratum-v1 --bench notify`

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::Network;
use bp_mining_job::{
    build_mining_job, CoinbaseTemplate, MiningJob, PayoutEntry, EXTRANONCE_SLOT_LEN,
};
use bp_stratum_v1::{build_notify_frame, swap_endian_words, ActiveSV1Template};
use criterion::{Criterion, Throughput};

// ── Counting allocator: tallies every alloc/realloc so we can read the
//    allocation count across one isolated call. ──
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const MERKLE_DEPTH_MAINNET: usize = 12;

/// One shared `MiningJob` — the same for every PPLNS client on a template.
fn make_job() -> MiningJob {
    build_mining_job(
        Network::Regtest,
        &[PayoutEntry {
            address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            sats: 5_000_000_000,
        }],
        &CoinbaseTemplate {
            block_height: 800_000,
            coinbase_value_sats: 5_000_000_000,
            witness_commitment: [0u8; 32],
        },
        "BP",
        EXTRANONCE_SLOT_LEN,
    )
    .expect("build_mining_job")
}

/// A realistic active template with the header hex cache populated the way the
/// production constructor does (`recompute_notify_header_hex` is private, so the
/// bench sets the public cache fields itself).
fn make_template(merkle_depth: usize) -> ActiveSV1Template {
    let mut t = ActiveSV1Template {
        template_id: 1,
        version: 0x2000_0000,
        prev_hash: [0x11; 32],
        n_bits: 0x1d00_ffff,
        header_timestamp: 0x6500_0001,
        network_target: [0xFF; 32],
        network_difficulty: 1.0,
        coinbase_prefix: vec![0xAA; 64],
        coinbase_tx_version: 2,
        coinbase_tx_input_sequence: 0xffff_ffff,
        coinbase_tx_value_remaining: 5_000_000_000,
        coinbase_tx_outputs: vec![0xBB; 40],
        coinbase_tx_outputs_count: 1,
        coinbase_tx_locktime: 0,
        merkle_path: vec![[0x33; 32]; merkle_depth],
        merkle_branch_hex: (0..merkle_depth)
            .map(|_| hex::encode([0x33u8; 32]))
            .collect(),
        prev_hash_hex: String::new(),
        version_hex: String::new(),
        n_bits_hex: String::new(),
        header_timestamp_hex: String::new(),
    };
    t.prev_hash_hex = hex::encode(swap_endian_words(&t.prev_hash));
    t.version_hex = format!("{:08x}", t.version);
    t.n_bits_hex = format!("{:08x}", t.n_bits);
    t.header_timestamp_hex = format!("{:08x}", t.header_timestamp);
    t
}

/// Allocations of one `build_notify_frame` call (cached header hex).
fn allocs_for_notify(t: &ActiveSV1Template, job: &MiningJob) -> usize {
    let before = ALLOCS.load(Ordering::Relaxed);
    let frame = build_notify_frame(black_box(t), black_box(job), "0000abcd", false);
    let n = ALLOCS.load(Ordering::Relaxed) - before;
    black_box(&frame);
    n
}

/// The hex encodings the caches remove from every per-client build — 4 on the
/// template (prev_hash + version + n_bits + ntime) and 2 on the shared
/// `MiningJob` (coinb1 + coinb2) — what the old `build_notify_frame` paid per call.
fn allocs_for_removed_encodes(t: &ActiveSV1Template, job: &MiningJob) -> usize {
    let before = ALLOCS.load(Ordering::Relaxed);
    let a = hex::encode(swap_endian_words(&t.prev_hash));
    let b = format!("{:08x}", t.version);
    let c = format!("{:08x}", t.n_bits);
    let d = format!("{:08x}", t.header_timestamp);
    let e = hex::encode(job.coinbase_prefix());
    let f = hex::encode(job.coinbase_suffix());
    let n = ALLOCS.load(Ordering::Relaxed) - before;
    black_box((&a, &b, &c, &d, &e, &f));
    n
}

fn report_allocs() {
    let t = make_template(MERKLE_DEPTH_MAINNET);
    let job = make_job();
    let _ = allocs_for_notify(&t, &job); // warm
    let cached = allocs_for_notify(&t, &job);
    let removed = allocs_for_removed_encodes(&t, &job);
    // Hard floor: the builder must make exactly one allocation — the single
    // pre-sized output frame Vec. Anything above means the `with_capacity`
    // upper bound in `build_notify_frame` was too small and the buffer
    // reallocated; widen it.
    // Hard floor: the builder must make exactly one allocation — the single
    // pre-sized output frame Vec. Anything above means the `with_capacity`
    // upper bound in `build_notify_frame` was too small and the buffer
    // reallocated; widen it.
    assert_eq!(
        cached, 1,
        "build_notify_frame regressed above 1 alloc/call — output buffer reallocated; \
         widen the with_capacity upper bound in build_notify_frame"
    );
    println!("\n=== allocations per mining.notify build (12-level merkle) ===");
    println!("  {cached:>3} alloc    build_notify_frame — the single pre-sized output frame Vec");
    println!("               (header + coinbase hex borrowed from caches; the buffer is sized");
    println!("                to an upper bound so serde_json writes it without a realloc)");
    println!("  {removed:>3} allocs   the per-client hex re-encodings the caches remove");
    println!("               (prev_hash + version + n_bits + ntime on the template,");
    println!("                coinb1 + coinb2 on the shared MiningJob — same for every client)");
    println!("               the old builder also grew the serde_json output Vec from its");
    println!("               128-byte default (~4 reallocs); pre-sizing collapses those to 1.");
    println!("======================================================\n");
}

fn bench(c: &mut Criterion) {
    let t = make_template(MERKLE_DEPTH_MAINNET);
    let job = make_job();
    let mut g = c.benchmark_group("sv1_build_notify");
    g.throughput(Throughput::Elements(1));
    g.bench_function("build_notify_frame (depth 12)", |b| {
        b.iter(|| {
            let f = build_notify_frame(black_box(&t), black_box(&job), "0000abcd", false);
            black_box(f)
        })
    });
    g.finish();
}

fn main() {
    report_allocs();
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}
