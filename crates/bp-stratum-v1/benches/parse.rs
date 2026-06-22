// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(unsafe_code)] // dev-only bench: a counting global allocator needs `unsafe impl GlobalAlloc`.
#![allow(clippy::print_stdout)] // dev-only bench: reporting alloc counts to stdout is the point.
//
//! Hot-path micro-benchmark for the SV1 JSON-RPC parser
//! ([`bp_stratum_v1::parse_request`]).
//!
//! Reports two numbers per message shape:
//!   - **allocations per parse** — the ckpool-relevant figure (ckpool's
//!     submit path is ~zero-alloc; ours currently builds a `serde_json::Value`
//!     DOM + owns each field as a `String`).
//!   - **ns/op** (criterion) — wall-clock per parse with warmup + outlier
//!     detection.
//!
//! Run: `cargo bench -p bp-stratum-v1 --bench parse`

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use bp_stratum_v1::parse_request;
use criterion::{Criterion, Throughput};

// ── Counting allocator: tallies every `alloc` call so we can read the
//    allocation count around a single isolated parse. Wraps the System
//    allocator (criterion's own allocations are not measured — we only
//    read the counter delta across one parse_request call). ──
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

/// The realistic hot-path lines. The `submit` ones dominate steady-state
/// traffic (one per accepted share); the others fire only at session open.
const SUBMIT_MASK: &str = r#"{"id":5,"method":"mining.submit","params":["bc1qaddr.worker1","1a2b","1122334455667788","65a1b2c3","deadbeef","1fffe000"]}"#;
const SUBMIT_NOMASK: &str = r#"{"id":5,"method":"mining.submit","params":["bc1qaddr.worker1","1a2b","1122334455667788","65a1b2c3","deadbeef"]}"#;
const AUTHORIZE: &str =
    r#"{"id":3,"method":"mining.authorize","params":["bc1qaddress.worker1","x"]}"#;
const SUBSCRIBE: &str = r#"{"id":1,"method":"mining.subscribe","params":["cgminer/4.11.1"]}"#;

const CASES: &[(&str, &str)] = &[
    ("submit (6 params, version mask)", SUBMIT_MASK),
    ("submit (5 params, no mask)", SUBMIT_NOMASK),
    ("authorize", AUTHORIZE),
    ("subscribe", SUBSCRIBE),
];

/// Allocations during exactly one `parse_request` of `line`. The result is
/// dropped AFTER the second read so its destructor's deallocs don't matter
/// (we count allocs, not net).
fn allocs_for(line: &str) -> usize {
    let before = ALLOCS.load(Ordering::Relaxed);
    let parsed = parse_request(black_box(line));
    let after = ALLOCS.load(Ordering::Relaxed);
    black_box(&parsed);
    after - before
}

fn report_allocs() {
    println!("\n=== allocations per parse (ckpool target: ~0) ===");
    for (name, line) in CASES {
        // Warm any one-time lazy statics first, then measure a clean call.
        let _ = allocs_for(line);
        let n = allocs_for(line);
        println!("  {n:>3} allocs   {name}");
    }
    println!("=================================================\n");
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse_request");
    for (name, line) in CASES {
        g.throughput(Throughput::Bytes(line.len() as u64));
        g.bench_function(*name, |b| {
            b.iter(|| {
                let r = parse_request(black_box(line));
                black_box(r)
            })
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
