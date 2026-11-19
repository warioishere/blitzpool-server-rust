-- The payout mode a found block was mined in, written by the front at the
-- find. The block reconcile reads it to tell a Solo block (no ledger to book)
-- from a block the pool owes a booking; no other process knows the mode.
--
-- Nullable without a default: catalog-only in PostgreSQL, a binary one
-- release older neither reads nor writes the column, and a row it inserts
-- reads as "mode unknown".

ALTER TABLE blocks_entity
  ADD COLUMN IF NOT EXISTS mode character varying(16);
