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

`cargo test --workspace` before pushing. CI covers fmt/clippy/check and the
suite, but the ~29 bitcoin-core regtests run **only locally** — a green CI does
not mean they passed. Check `grep -c skipping` is 0: missing infrastructure
makes tests skip while cargo still reports "ok".
