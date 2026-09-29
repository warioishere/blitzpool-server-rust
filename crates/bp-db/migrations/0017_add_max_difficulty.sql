-- The highest single share difficulty per 10-minute slot, pool-wide and per
-- client row, for the "best share per slot" charts. Written by the same
-- batched stats flush as the sums beside it, merged with GREATEST instead of
-- added.
--
-- A plain ADD COLUMN with a constant default: catalog-only in PostgreSQL, no
-- table rewrite, and a binary one release older keeps writing its rows (the
-- column takes the default).

ALTER TABLE pool_share_statistics_entity
  ADD COLUMN IF NOT EXISTS "maxDifficulty" REAL DEFAULT 0 NOT NULL;

ALTER TABLE client_statistics_entity
  ADD COLUMN IF NOT EXISTS "maxDifficulty" REAL DEFAULT 0 NOT NULL;
