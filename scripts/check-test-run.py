#!/usr/bin/env python3
"""Decide whether a `cargo test` log is evidence, rather than just green.

    cargo test --workspace --release --no-fail-fast -- --nocapture 2>&1 | tee /tmp/run.log
    ./scripts/check-test-run.py /tmp/run.log

Exit 0 only if the run proves something. Three things can make a green suite
meaningless here, and none of them show up in `$?`:

1. **A skipped test passes.** `connect_pg_or_skip` and friends return `None`
   and the test returns early, so an unreachable Postgres is indistinguishable
   from a passing one. Measured 2026-08-10: the Docker daemon died mid-run and
   the totals were *identical* to the healthy run — 2104 passed either way.
   Only the skip-line count told them apart, so that count is checked here and
   is never hardcoded to an expected value.
2. **A regtest that skipped finishes in milliseconds.** Duration is the
   evidence the node actually booted, which is why each `Running` line is
   paired with the `test result:` line that follows it instead of eyeballed.
3. **A whole binary can vanish.** A `bitcoin-node` discovery regression drops
   the regtest binary count without failing anything, so the count is asserted
   against --expect-regtest-binaries.

Deliberately no expected passed-count: the total is tree-dependent, so it is
only comparable against a run on the same commit. Coverage is established by
the per-binary durations and the binary count, not by the total.
"""
import argparse
import re
import sys

# A regtest that boots a node cannot finish faster than this; one that
# skipped cannot take longer. Measured: the fastest real regtest is ~2s,
# every skipped one is <0.05s, so anywhere in between separates them.
TRIVIAL_SECONDS = 0.5

RUNNING = re.compile(r"Running (?:unittests |tests[/\\])?(\S+)")
RESULT = re.compile(
    r"test result: (?:\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;"
    r".*?finished in ([\d.]+)s"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", help="captured `cargo test` output")
    ap.add_argument(
        "--expect-regtest-binaries",
        type=int,
        default=23,
        help="how many regtest_* binaries must appear (0 disables the check)",
    )
    args = ap.parse_args()

    with open(args.logfile, errors="replace") as fh:
        log = fh.read().splitlines()

    # Pair each `Running <binary>` with the next `test result:`. Doctest and
    # summary result lines have no preceding Running line and are counted in
    # the totals only.
    binaries, pending = [], None
    totals = [0, 0, 0]  # passed, failed, ignored
    for line in log:
        m = RUNNING.search(line)
        if m:
            pending = m.group(1)
            continue
        m = RESULT.search(line)
        if not m:
            continue
        passed, failed, ignored, secs = (
            int(m.group(1)),
            int(m.group(2)),
            int(m.group(3)),
            float(m.group(4)),
        )
        totals[0] += passed
        totals[1] += failed
        totals[2] += ignored
        if pending is not None:
            binaries.append((pending, passed, secs))
            pending = None

    if not binaries:
        print(f"FAIL: no `Running`/`test result:` pairs in {args.logfile} — "
              "wrong file, or the run died before any binary reported")
        return 1

    regtests = [b for b in binaries if "regtest_" in b[0]]
    skips = [l for l in log if "skipping" in l.lower()]
    trivial = [name for name, _, secs in regtests if secs < TRIVIAL_SECONDS]

    passed, failed, ignored = totals
    print(f"TOTAL passed / failed / ignored : {passed} / {failed} / {ignored}")
    print(f"regtest_* binaries             : {len(regtests)}")
    print(f"regtest tests (sum of passed)  : {sum(p for _, p, _ in regtests)}")
    print(f"aggregate regtest node time    : {sum(s for _, _, s in regtests):.1f}s")
    print()
    for name, p, secs in sorted(regtests, key=lambda b: -b[2]):
        flag = "ran" if secs >= TRIVIAL_SECONDS else "SUSPECT: likely skipped"
        print(f"{name:<52} {p:>3} passed {secs:>7.2f}s  {flag}")

    print(f"\nlines containing 'skipping': {len(skips)}")
    for s in skips[:30]:
        print("  " + s.strip())
    if len(skips) > 30:
        print(f"  … and {len(skips) - 30} more")

    print()
    problems = []
    if failed:
        problems.append(f"{failed} failing tests")
    if trivial:
        problems.append(
            f"{len(trivial)} regtest binaries under {TRIVIAL_SECONDS}s "
            f"(skipped, not run): {trivial}"
        )
    if skips:
        problems.append(
            f"{len(skips)} skip lines — a skipped test passes, so the "
            "passed-count above is not evidence"
        )
    if args.expect_regtest_binaries and len(regtests) != args.expect_regtest_binaries:
        problems.append(
            f"{len(regtests)} regtest binaries, expected "
            f"{args.expect_regtest_binaries} — a binary that never ran cannot fail"
        )
    # `--nocapture` is what makes the skip count meaningful: cargo swallows the
    # output of passing tests, and a skipped test passes, so without it the
    # "0 skip lines" above would be unfalsifiable.
    if not skips and not any("running 1 test" in l or "--nocapture" in l for l in log):
        print("NOTE: could not confirm --nocapture from this log; 0 skip lines "
              "means nothing without it")

    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1

    print(f"OK: {passed} passed, 0 failed, 0 ignored, 0 skip lines; all "
          f"{len(regtests)} regtest binaries ran non-trivially")
    return 0


if __name__ == "__main__":
    sys.exit(main())
