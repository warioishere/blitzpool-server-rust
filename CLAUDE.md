# blitzpool-rust — how to work in this codebase

A non-custodial Bitcoin mining pool. Coinbase outputs pay miners directly, so
an accounting mistake is not a wrong number in a database — it is satoshis
that went to the wrong address and cannot be recalled.

## The one failure mode this codebase actually has

Not "someone wrote a bug". **The same concept implemented twice, drifting.**
Three payout modes (PPLNS, Group-Solo, Blockparty) do similar work, and every
time one of them was changed alone, the other kept the old behaviour until
someone noticed. Rust's exhaustive `match` protects against a *forgotten mode*;
nothing protects against a *forgotten twin*.

Recorded instances, so this is not an abstraction:

- **2026-07-25 / 07-26** — "book the distribution the found block's coinbase
  actually paid" was found and fixed twice, in two PRs (#5, #6), a day apart.
  For that day one mode was correct and the other was not.
- **2026-08-01 → 08-02 → 08-03** — the weight model made it possible to
  recompute a block's settlement at apply time, which removed the reason PPLNS
  froze a *computed result* at found-time. Nobody asked what that constraint
  had been holding up. A day later a real money bug (the dust sweep undoing
  its own pair-cancel) got patched *inside* the old design with a 78-line
  re-base pass. A day after that, the cause was removed and the patch, the
  flush-before-freeze rule and two pending-block formats went with it.
- The pure-math crate `bp-group-solo` outlived its only caller by two days
  without a single compiler warning.
- **2026-08-03** — a found block's settlement inputs were stamped into the
  block-found event by `if resolved.mode == MiningMode::GroupSolo`. PPLNS fell
  out of that `if` and read its snapshot ~20 min later instead, against a
  20-minute TTL, so roughly half its blocks lost the inputs for good. Several
  reviews had passed over the line. The `match` that replaced it would not have
  compiled with a mode missing.

## Rules that follow from it

1. **Touching one payout mode? Say what the other two do here.** Either change
   them together or state why they legitimately differ.
2. **One concept, one implementation.** If you find yourself writing something
   that already exists for another mode, share it instead —
   `bp_coinbase_snapshot::build_and_snapshot` and the shared `PendingBlock` are
   what that looks like.
3. **When an assumption dies, hunt its scaffolding the same day.** Grep for the
   things that only made sense under it. They will still compile.
4. **Verify before claiming a cause.** Every "why" in this file was checked
   against `git log`, not remembered.
5. **Branch on a mode with `match`, never with `if mode ==`.** An `if` cannot
   be exhaustive, so it is where a mode goes missing without anything
   complaining — that is not a hypothetical, it is the 2026-08-03 entry above.
   The same goes for `is_some()` on a per-mode field: it reads as a mode test
   and answers a different question.

## Money invariants — do not weaken these to make a refactor fit

- The pool takes its fee and nothing more. PPLNS: value withheld from a miner
  stays inside the miners' cut. Group-Solo: it goes to the pool, deliberately
  and by operator decision — see `bp_pplns::WithheldValue`.
- What gets booked comes from the block's **own coinbase**, never from what the
  pool intended to pay.
- Group-Solo keeps **no ledger**. That holds only while every member fits in
  the coinbase, which is why `GroupService` refuses a join past
  `max_coinbase_outputs`. Do not raise one without the other.

## Testing

`cargo test --workspace -- --nocapture` before pushing. CI covers
fmt/clippy/check and the suite, but the ~29 bitcoin-core regtests run **only
locally** — a green CI does not mean they passed.

**A green suite here is not evidence until you have checked these three.**

1. **The services must be up.** Every Redis/Postgres-backed test calls
   `connect_or_skip`, which returns `None` and makes the test *pass* when the
   service is unreachable. Start them first:
   ```bash
   docker start bp-test-pg bp-test-redis   # 15433 / 16379
   ```
   New migrations (`crates/bp-db/migrations/`) are NOT applied to those
   containers automatically. A stale schema surfaces first as a
   `cargo sqlx prepare` failure on the missing column — compile-time is
   stricter here than the tests, which only notice if they touch it.
2. **`--nocapture`, or the skip check is a lie.** `cargo test` swallows the
   output of *passing* tests, and a skipped test passes — so its "… skipping"
   line never reaches the log and `grep -c skipping` reports 0 on a run where
   everything skipped. It confirms exactly what it was meant to refute. Only
   with `--nocapture` does the count mean anything.
3. **Watch the passed-count, not the exit code.** Adding N tests must move it
   by N. A skipped test is indistinguishable from a passing one in `$?`.

Measured 2026-08-03: the containers had been down five days, the whole
integration suite was skipping, `grep -c skipping` said 0, and two new tests
reported green while proving nothing.

**Writing a money test: use real addresses.** `build_weight_distribution`
drops every entry `bitcoin::Address` cannot parse, so a `format!("{prefix}aaa")`
address yields an EMPTY distribution — and the miners then surface as 0-sat
"late arriver" rows, so `history_inserted >= 1` still holds and the test passes
without ever exercising a payout. Assert a precondition that pins the shape you
meant to build (the miner is in `distribution.entries`, or is absent from
`actual.paid_by_address` when you meant it withheld).

**A test that claims a safeguard must be shown to fail without it.** Run it
against the unfixed code first, or pair it with the negative control in the
same test — `a_block_settles_from_its_parked_blob_after_the_snapshot_key_is_gone`
asserts both directions, so it cannot pass on a precondition that silently
did not hold.
