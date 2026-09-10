-- Payout identity: one row per miner, either a fixed address or a rotating
-- (xpub-derived) descriptor. The database half of `bp_common::PayoutIdentity`.
--
-- Why a table and not two nullable columns on an existing one: the identity is
-- the thing every payout mode agrees on, and it has exactly one owner. Hanging
-- it off `pplns_balance` would make it PPLNS's, and Group-Solo and Blockparty
-- would grow their own copy — which is the failure mode `CLAUDE.md` opens with.
--
-- `kind` mirrors the Rust sum type, and the CHECK makes the half-populated
-- states unrepresentable HERE as well as in Rust. That matters because Rust's
-- guarantee stops at the connection: a psql session, an admin script, or a
-- future ORM can all write a row this process would never construct. Without
-- the constraint, `kind = 'rotating'` with a NULL descriptor is a row that
-- parses as a rotating identity and derives no script — discovered at coinbase
-- assembly, for a template, on the money path.
--
-- Deliberately NOT stored: a derived address, or the current derivation height.
-- A rotating identity's script is a pure function of (descriptor, height) and
-- the height comes from the block being built, so caching either here would
-- create a second answer to "which script does this miner get at H" — and per
-- `CLAUDE.md`, two implementations of one concept is the bug this codebase
-- actually has.
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has this table, so this migration is a no-op there.
CREATE TABLE IF NOT EXISTS miner_identity (
    -- The ledger key. For 'static' this IS the payout address; for 'rotating'
    -- it is `xpb` + base58(sha256(descriptor)) — 47 chars, which is why the
    -- encoding is base58 and not hex (64 would not fit this column, nor the
    -- other 26 like it). See bp-payout-descriptor's PAYOUT_ID_PREFIX.
    "payoutId" character varying(62) NOT NULL,

    -- 'static' | 'rotating'. Constrained rather than free text so an unknown
    -- kind cannot be inserted and then met by a Rust `match` that has no arm
    -- for it.
    kind character varying(16) NOT NULL,

    -- Exactly one of these is populated, per the CHECK below.
    --
    -- 'static': the payout address, verbatim and already normalized by
    -- `bp_common::normalize_btc_address` (bech32 lowercased, base58 case
    -- preserved).
    address character varying(62),

    -- 'rotating': the canonical output descriptor the pool built around the
    -- miner's xpub, e.g. `wpkh(xpub…/0/*)#checksum`. TEXT because a descriptor
    -- is ~130 characters and grows with any future script type — the 62-char
    -- identity shape applies to the ledger key, never to this.
    --
    -- This is a wallet-watching capability, not a spending one. It must not be
    -- logged (see bp-payout-descriptor's credential rule) and it must not be
    -- returned by any miner-facing endpoint that is not authenticated as its
    -- owner.
    descriptor text,

    "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,

    CONSTRAINT miner_identity_pkey PRIMARY KEY ("payoutId"),

    -- The sum type, as a constraint. Written as one CHECK over both columns
    -- rather than a NOT NULL on each, because "exactly one of these" is a
    -- single fact about the row and splitting it would let the two halves
    -- drift.
    CONSTRAINT "CHK_miner_identity_kind_populated" CHECK (
        (kind = 'static'   AND address    IS NOT NULL AND descriptor IS NULL)
        OR
        (kind = 'rotating' AND descriptor IS NOT NULL AND address    IS NULL)
    )
);

-- Backfill every miner the pool already pays as 'static', with a straight
-- column copy from `pplns_balance` — the one table that holds a row for every
-- address the pool has ever owed money to.
--
-- **This backfill is deliberately incomplete, and that is safe only because of
-- what a missing row means.** `pplns_balance` covers PPLNS; a Solo miner who
-- has never accrued a pending balance, and a Group-Solo member (that mode keeps
-- no ledger at all, per `CLAUDE.md`), get no row here. So absence must mean
-- "static, pay the address verbatim" — the behaviour every mode has today — and
-- must never mean "unknown, refuse to pay" or "look it up somewhere else".
--
-- Stated as a rule for the phases that consume this table: a payout path reads
-- this table to discover that an identity ROTATES. It must not read it to
-- discover where to pay a static one, because for most static miners the answer
-- is not in here. That keeps the backfill's coverage off the money path
-- entirely — a row that is missing changes nothing.
--
-- **No `addr(<address>)` descriptor sentinel.** The tempting move is to give
-- every row a descriptor so the column can be NOT NULL, spelling a static
-- address as the descriptor `addr(bc1q…)`. It was withdrawn from the design for
-- a reason that applies unchanged here: `addr()` has no wildcard, so its safety
-- depends on a rejection rule living in a *different* module (intake's
-- `has_wildcard` assertion) remembering to refuse it. That is a non-local
-- invariant, and the whole point of the sum type is that the invariant is
-- local. A static identity has no descriptor; the column is NULL and the CHECK
-- says so.
--
-- ON CONFLICT DO NOTHING so re-running is a no-op and so a row already written
-- by the new code (a rotating one, in particular) is never overwritten by a
-- static backfill.
INSERT INTO miner_identity ("payoutId", kind, address)
SELECT address, 'static', address
  FROM pplns_balance
 WHERE address IS NOT NULL
   AND address <> ''
ON CONFLICT ("payoutId") DO NOTHING;

-- Rotating identities are the ones a support query looks up by descriptor
-- ("this miner says they configured xpub X — what did we build?"). Partial, so
-- it indexes only the rows that have one.
CREATE INDEX IF NOT EXISTS "IDX_miner_identity_descriptor"
    ON miner_identity (descriptor)
 WHERE descriptor IS NOT NULL;

CREATE INDEX IF NOT EXISTS "IDX_miner_identity_kind"
    ON miner_identity (kind);
