// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(unsafe_code)] // dev-only bench: a counting global allocator needs `unsafe impl GlobalAlloc`.
#![allow(clippy::print_stdout)] // dev-only bench: reporting alloc counts to stdout is the point.
//! Micro-benchmark of the SV2 extended-channel share path
//! ([`bp_stratum_v2::mining::submit::validate_submit_extended`]): allocations
//! per call (one, the `Box<ShareAccept>`) and ns/op, which is hash-bound and
//! scales with merkle depth. Run: `cargo bench -p bp-stratum-v2 --bench submit`

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use bp_jobs_lifecycle::LifecycleConfig;
use bp_share::{calculate_difficulty, Difficulty};
use bp_stratum_v2::mining::channel::ChannelState;
use bp_stratum_v2::mining::jobs::ExtendedJob;
use bp_stratum_v2::mining::submit::{
    validate_submit_extended, ExtendedChannelView, ExtranonceBytes, SubmitSharesExtendedInput,
};
use criterion::{BatchSize, Criterion, Throughput};

// Counting allocator; only the delta around one isolated call is read, so
// criterion's own allocations do not count.
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

// Mainnet-shaped inputs (~12 merkle levels). The job difficulty is trivial so
// the share is Accepted, while n_bits stays out of reach so it is never a
// block candidate (no witness-coinbase assembly).

const MERKLE_DEPTH_MAINNET: usize = 12;
const MERKLE_DEPTH_SHALLOW: usize = 1;

fn ext_channel() -> ChannelState {
    // channel_id=2, 4-byte extranonce prefix, 8-byte extranonce size.
    ChannelState::new_extended(
        2,
        vec![0u8; 4],
        8,
        Difficulty(1024.0),
        [0xFF; 32],
        LifecycleConfig::DEFAULT,
    )
}

fn ext_job(merkle_depth: usize) -> ExtendedJob {
    ExtendedJob {
        payouts_fingerprint: [0u8; 32],
        coinbase_prefix: vec![0xAA; 64],
        coinbase_suffix: vec![0xBB; 100],
        merkle_path: vec![[0x33; 32]; merkle_depth],
        // Same 4-byte prefix `ext_channel()` opens with — the validator
        // splices the job's copy into the coinbase.
        extranonce_prefix: vec![0u8; 4],
        version: 0x2000_0000,
        prev_hash: [0x11; 32],
        n_bits: 0x1d00_ffff,
        min_ntime: 0,
        // Trivially easy → target ≈ MAX → any hash meets it → Accepted.
        difficulty: Difficulty(1.0 / 4_294_967_296.0),
        coinbase_tx_value_remaining: 5_000_000_000,
        template_id: Some(1),
        jdp_claims_the_block: false,
        created_at: 0,
        retired_at: None,
    }
}

/// `nonce` must vary per call: a repeated one short-circuits on
/// `duplicate-share` and never reaches the hash path.
fn ext_submission(nonce: u32) -> SubmitSharesExtendedInput {
    SubmitSharesExtendedInput {
        channel_id: 2,
        sequence_number: 1,
        job_id: 7,
        nonce,
        version: 0x2000_0000,
        ntime: 0x6500_0001,
        extranonce: ExtranonceBytes::from_slice(&[0x11; 8]),
        tlvs: Vec::new(),
    }
}

/// One accepted `validate_submit_extended` call, with the same channel
/// projection the handler does inline to avoid a per-share job clone.
fn run_validate(channel: &mut ChannelState, sub: &SubmitSharesExtendedInput, job: &ExtendedJob) {
    let job_target = channel.target_for(job.difficulty);
    let view = ExtendedChannelView {
        kind: channel.kind,
        extranonce_size: channel.extranonce_size,
        job_target,
        job_lifecycle: *channel.standard_jobs.lifecycle(),
    };
    let v = validate_submit_extended(
        &mut channel.seen_shares,
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

/// Baseline: `run_validate` plus a job clone, so the difference is its cost.
fn run_validate_with_clone(
    channel: &mut ChannelState,
    sub: &SubmitSharesExtendedInput,
    job: &ExtendedJob,
) {
    let cloned = black_box(job.clone());
    run_validate(channel, sub, &cloned);
}

/// A channel warmed by `n` accepted shares (nonces `0..n`), so the next insert
/// measures steady state rather than a one-off table resize.
fn warmed_channel_n(job: &ExtendedJob, n: u32) -> ChannelState {
    let mut channel = ext_channel();
    for nonce in 0..n {
        run_validate(&mut channel, &ext_submission(nonce), job);
    }
    channel
}

/// Steady-state allocations of one accepted share on a pre-grown dedup set.
fn allocs_for_validate(depth: usize) -> usize {
    let job = ext_job(depth);
    let mut channel = warmed_channel_n(&job, 512);
    let sub = ext_submission(512); // unique vs the 0..512 warm shares
    let before = ALLOCS.load(Ordering::Relaxed);
    run_validate(&mut channel, &sub, &job);
    ALLOCS.load(Ordering::Relaxed) - before
}

/// Baseline counterpart of [`allocs_for_validate`]: clone + validate.
fn allocs_for_validate_with_clone(depth: usize) -> usize {
    let job = ext_job(depth);
    let mut channel = warmed_channel_n(&job, 512);
    let sub = ext_submission(512);
    let before = ALLOCS.load(Ordering::Relaxed);
    run_validate_with_clone(&mut channel, &sub, &job);
    ALLOCS.load(Ordering::Relaxed) - before
}

/// Allocations of one `bp_share::calculate_difficulty` call.
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

    // Clone baseline vs validate-only. A fresh channel per iteration (untimed)
    // keeps every timed submit unique, avoiding the duplicate-share short-circuit.
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

    {
        let header = [0xABu8; 80];
        g.bench_function("calculate_difficulty (f64, post-C1)", |b| {
            b.iter(|| black_box(calculate_difficulty(black_box(&header))))
        });
    }

    // Cost of a per-share job clone, which the handler avoids through
    // disjoint-field borrows (baseline).
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
