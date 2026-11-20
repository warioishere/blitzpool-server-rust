-- When a Team's admin last reset the round by hand, outside the schedule:
-- the manual reset's cooldown reads it, and the Team's members see it.
-- NULL for a Team that never had one.
--
-- A nullable column: a binary one release older names its columns in every
-- statement on `pplns_group`, so it neither reads nor writes this one.

ALTER TABLE pplns_group
  ADD COLUMN IF NOT EXISTS "lastManualRoundResetAt" bigint;
