// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(unsafe_code)] // dev-only bench: a counting global allocator needs `unsafe impl GlobalAlloc`.
#![allow(clippy::print_stdout)] // dev-only bench: reporting alloc counts to stdout is the point.
//
//! Hot-path micro-benchmark for the SV2 **extended-channel** share path
//! ([`bp_stratum_v2::mining::submit::validate_submit_extended`]), the
//! steady-state work done once per submitted share.
//!
//! Two figures per case:
//!   - **allocations per call** — the leanness metric. A validated share
//!     now costs 1 alloc: the `Box<ShareAccept>`. The coinbase txid is
//!     streamed straight into the hasher (`sha256d_from_parts`, no coinbase
//!     `Vec`), the merkle walk and worker-name resolver are zero-alloc, and —
//!     since C1 — `bp_share::calculate_difficulty` (now `f64`, was
//!     `num-bigint`) is too. The separately-measured `ext_job clone` is the
//!     per-share `ExtendedJob` copy the extended handler used to make to
//!     release the channel-map borrow — since removed via disjoint-field
//!     borrows (kept here as a baseline).
//!   - **ns/op** (criterion) — wall-clock, dominated by the per-merkle-level
//!     SHA-256d (so it scales with merkle depth) plus the coinbase + header
//!     double-hashes.
//!
//! Findings: the SV2 share path is hash-bound, not parse-bound (unlike
//! SV1). Three allocation sources were removed: the ext_job clone (B,
//! 3 allocs/share, disjoint-field borrows), the num-bigint difficulty
//! calc (C1, ~6 allocs/share, now f64 in `bp_share`), and the coinbase
//! buffer (streamed via `sha256d_from_parts`, no per-share `Vec`). A
//! validated share is down to 1 alloc (`Box<ShareAccept>`); the hashing
//! itself is irreducible verifier work.
//!
//! Run: `cargo bench -p bp-stratum-v2 --bench submit`

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use bp_share::{calculate_difficulty, Difficulty};
use bp_stratum_v2::mining::channel::ChannelState;
use bp_stratum_v2::mining::jobs::ExtendedJob;
use bp_stratum_v2::mining::submit::{
    validate_submit_extended, ExtendedChannelView, ExtranonceBytes, SubmitSharesExtendedInput,
};
use criterion::{BatchSize, Criterion, Throughput};

// ── Counting allocator: tallies every `alloc`/`realloc` so we can read
//    the allocation count across a single isolated call. Wraps System;
//    criterion's own allocations are not measured — we only read the
//    counter delta around one call. ──
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

// ── Realistic inputs ─────────────────────────────────────────────────
//
// Mainnet-shaped: an 8-byte negotiated extranonce, a coinbase split into
// a ~64-byte prefix and ~100-byte suffix, and a merkle path whose depth
// matches a real block (~3–4k txs → ~12 levels). The job difficulty is
// set trivially easy so the share is Accepted (the hot path), and the
// pinned network difficulty is set unreachably hard so it is NOT a
// block-candidate (no witness-coinbase assembly).

const MERKLE_DEPTH_MAINNET: usize = 12;
const MERKLE_DEPTH_SHALLOW: usize = 1;

fn ext_channel() -> ChannelState {
    // channel_id=2, 4-byte extranonce prefix, 8-byte extranonce size.
    ChannelState::new_extended(2, vec![0u8; 4], 8, Difficulty(1024.0), [0xFF; 32])
}

fn ext_job(merkle_depth: usize) -> ExtendedJob {
    ExtendedJob {
        coinbase_prefix: vec![0xAA; 64],
        coinbase_suffix: vec![0xBB; 100],
        merkle_path: vec![[0x33; 32]; merkle_depth],
        version: 0x2000_0000,
        prev_hash: [0x11; 32],
        n_bits: 0x1d00_ffff,
        min_ntime: 0,
        // Trivially easy → target ≈ MAX → any hash meets it → Accepted.
        difficulty: Difficulty(1.0 / 4_294_967_296.0),
        // Unreachably hard → never a block candidate (no witness assembly).
        network_difficulty: Difficulty(1e15),
        coinbase_tx_value_remaining: 5_000_000_000,
        template_id: Some(1),
        created_at: 0,
        retired_at: None,
    }
}

/// `nonce` is varied per call: `validate_submit_extended` inserts every
/// accepted share into the channel dedup cache, so re-submitting the same
/// nonce would short-circuit on `duplicate-share` and never exercise the
/// hash path. Each measured share must therefore be unique.
fn ext_submission(nonce: u32) -> SubmitSharesExtendedInput {
    SubmitSharesExtendedInput {
        channel_id: 2,
        sequence_number: 1,
        job_id: 7,
        nonce,
        version: 0x2000_0000,
        ntime: 0x6500_0001,
        extranonce: ExtranonceBytes::from_slice(&[0x11; 8]),
        tail_tlvs: Vec::new(),
    }
}

/// One `validate_submit_extended` call (Accept path). Projects the
/// channel into the `ExtendedChannelView` + `&mut submission_cache` the
/// validator takes — the same projection the handler does inline to avoid
/// the per-share `ExtendedJob` clone.
fn run_validate(channel: &mut ChannelState, sub: &SubmitSharesExtendedInput, job: &ExtendedJob) {
    let job_target = channel.target_for(job.difficulty);
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_prefix: &channel.extranonce_prefix,
        extranonce_size: channel.extranonce_size,
        job_target,
    };
    let v = validate_submit_extended(
        &mut channel.submission_cache,
        &view,
        sub,
        job,
        job.difficulty,
        1_000,
        false,
        false,
    );
    black_box(&v);
}

/// Pre-B per-share work: the old handler cloned the whole `ExtendedJob`
/// out of the channel map, then validated against that clone. The
/// validation work is identical to `run_validate`; the only difference is
/// the clone. Used for the before/after comparison.
fn run_validate_with_clone(
    channel: &mut ChannelState,
    sub: &SubmitSharesExtendedInput,
    job: &ExtendedJob,
) {
    let cloned = black_box(job.clone());
    run_validate(channel, sub, &cloned);
}

/// A channel warmed by `n` accepted shares (nonces `0..n`). Warms the
/// target memo and — for `n` large enough — grows the dedup HashSet past
/// its realloc points so a subsequent insert measures steady state
/// rather than a one-off table resize.
fn warmed_channel_n(job: &ExtendedJob, n: u32) -> ChannelState {
    let mut channel = ext_channel();
    for nonce in 0..n {
        run_validate(&mut channel, &ext_submission(nonce), job);
    }
    channel
}

/// Steady-state allocations of one accepted share: the dedup set is
/// pre-grown (warm with 512 shares) so the measured share #512 does not
/// pay a HashSet resize — isolating the irreducible per-share allocs.
fn allocs_for_validate(depth: usize) -> usize {
    let job = ext_job(depth);
    let mut channel = warmed_channel_n(&job, 512);
    let sub = ext_submission(512); // unique vs the 0..512 warm shares
    let before = ALLOCS.load(Ordering::Relaxed);
    run_validate(&mut channel, &sub, &job);
    ALLOCS.load(Ordering::Relaxed) - before
}

/// Pre-B counterpart of [`allocs_for_validate`]: clone + validate.
fn allocs_for_validate_with_clone(depth: usize) -> usize {
    let job = ext_job(depth);
    let mut channel = warmed_channel_n(&job, 512);
    let sub = ext_submission(512);
    let before = ALLOCS.load(Ordering::Relaxed);
    run_validate_with_clone(&mut channel, &sub, &job);
    ALLOCS.load(Ordering::Relaxed) - before
}

/// Allocations of one `bp_share::calculate_difficulty` call — the
/// num-bigint target→difficulty conversion done once per share inside the
/// validator. Isolated here because it dominates the validator's
/// allocation count.
fn allocs_for_difficulty_calc() -> usize {
    let header = [0xABu8; 80];
    let _ = black_box(calculate_difficulty(&header)); // warm lazy statics
    let before = ALLOCS.load(Ordering::Relaxed);
    let d = black_box(calculate_difficulty(&header));
    let n = ALLOCS.load(Ordering::Relaxed) - before;
    black_box(&d);
    n
}

fn report_allocs() {
    let before_b = allocs_for_validate_with_clone(MERKLE_DEPTH_MAINNET);
    let after_b = allocs_for_validate(MERKLE_DEPTH_MAINNET);
    println!("\n=== B before/after — per-share submit path allocations (12-level merkle) ===");
    println!("  {before_b:>3} allocs   BEFORE B  (ext_job clone + validate)");
    println!("  {after_b:>3} allocs   AFTER B   (validate only)            ← clone removed");
    println!(
        "  {:>3} allocs   = saved by B ({} ext_job Vec copies)",
        before_b - after_b,
        before_b - after_b
    );

    println!("\n=== allocations per accepted share (post-B, post-C1 breakdown) ===");
    println!(
        "  {:>3} allocs   validate_submit_extended (12-level merkle, Accept)",
        after_b
    );
    println!(
        "  {:>3} allocs     └─ of which: bp_share::calculate_difficulty   ← C1: now f64 (was 6, num-bigint)",
        allocs_for_difficulty_calc()
    );
    println!("                   (the remaining alloc is the Box<ShareAccept>; the coinbase txid");
    println!("                    is streamed, merkle walk + worker-name resolver are zero-alloc)");
    println!("======================================================\n");
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("sv2_submit_extended");

    // B before/after at mainnet merkle depth: the only per-share-path
    // difference is the ext_job clone. `iter_batched_ref` rebuilds a
    // freshly-warmed channel per iteration (untimed setup) so every timed
    // submit is unique — avoiding the duplicate-share short-circuit while
    // keeping the cache size ≤1.
    {
        let job = ext_job(MERKLE_DEPTH_MAINNET);
        let sub = ext_submission(1);
        g.throughput(Throughput::Elements(1));
        g.bench_function("B BEFORE: clone + validate (depth 12)", |b| {
            b.iter_batched_ref(
                || warmed_channel_n(&job, 1),
                |channel| run_validate_with_clone(channel, &sub, &job),
                BatchSize::SmallInput,
            )
        });
        g.bench_function("B AFTER: validate only (depth 12)", |b| {
            b.iter_batched_ref(
                || warmed_channel_n(&job, 1),
                |channel| run_validate(channel, &sub, &job),
                BatchSize::SmallInput,
            )
        });
    }

    // The necessary work across merkle depths (post-B): build coinbase +
    // walk merkle + double-hash header. Scales with merkle depth.
    for depth in [MERKLE_DEPTH_SHALLOW, MERKLE_DEPTH_MAINNET] {
        let job = ext_job(depth);
        let sub = ext_submission(1); // unique vs the nonce-0 warm share
        g.throughput(Throughput::Elements(1));
        g.bench_function(format!("validate (merkle depth {depth})"), |b| {
            b.iter_batched_ref(
                || warmed_channel_n(&job, 1),
                |channel| run_validate(channel, &sub, &job),
                BatchSize::SmallInput,
            )
        });
    }

    // The difficulty conversion inside the validator, isolated. C1 made
    // this f64 (was num-bigint, ~6 allocs + ~300ns/share).
    {
        let header = [0xABu8; 80];
        g.bench_function("calculate_difficulty (f64, post-C1)", |b| {
            b.iter(|| black_box(calculate_difficulty(black_box(&header))))
        });
    }

    // The per-share cost the disjoint-borrow refactor removed from the
    // handler (kept here as a documented baseline of what was eliminated).
    for depth in [MERKLE_DEPTH_SHALLOW, MERKLE_DEPTH_MAINNET] {
        let job = ext_job(depth);
        g.bench_function(format!("ext_job clone (merkle depth {depth})"), |b| {
            b.iter(|| black_box(job.clone()))
        });
    }

    g.finish();
}

fn main() {
    report_allocs();
    let mut c = Criterion::default().configure_from_args();
    bench(&mut c);
    c.final_summary();
}
