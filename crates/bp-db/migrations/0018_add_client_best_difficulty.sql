-- The session's own best share difficulty, on the row that lives exactly as
-- long as the connection. A paused miner keeps its best, which a TTL-bound
-- Redis field cannot. Written only when a flush beats the stored value, so the
-- write rate follows new records, not shares.
--
-- A plain ADD COLUMN with a constant default: catalog-only in PostgreSQL, no
-- table rewrite, and a binary one release older keeps inserting rows.

ALTER TABLE client_entity
  ADD COLUMN IF NOT EXISTS "bestDifficulty" double precision NOT NULL DEFAULT 0;
