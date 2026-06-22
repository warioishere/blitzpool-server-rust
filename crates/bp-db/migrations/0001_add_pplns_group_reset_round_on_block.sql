-- Per-group toggle: reset the Group-Solo round on every block-found.
--
-- Default false: the round is NOT wiped per block, so shares accumulate
-- across blocks until a calendar preset or manual reset fires. A group opts
-- into the legacy per-block reset via the admin settings API. Existing groups
-- get false too (the column default backfills every row).
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has the column, so this is a no-op there; an existing DB without it
-- gets the column added.
ALTER TABLE pplns_group
    ADD COLUMN IF NOT EXISTS "resetRoundOnBlock" boolean NOT NULL DEFAULT false;
