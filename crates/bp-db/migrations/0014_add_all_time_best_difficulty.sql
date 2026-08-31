-- A permanent, reset-immune record for the public high-score list.
--
-- Why: `/api/info` -> `highScores` read `address_settings_entity.
-- "bestDifficulty"` — the exact column `/bestdiff_reset` zeroes. So a
-- miner clearing their own best also erased their entry from the pool's
-- public leaderboard, and `GREATEST` cannot bring it back: the flush
-- only re-establishes from the CURRENT window's max, never from
-- history. Measured 2026-08-30: an 8.23T record held rank 3 for three
-- days until its owner ran `/bestdiff_reset`; hours later the row had
-- rebuilt to 880 Mio from recent shares and the record was gone for
-- good.
--
-- The split: `"bestDifficulty"` stays the miner's own, resettable
-- value (their dashboard, the push-notification baseline).
-- `"allTimeBestDifficulty"` is the pool's record and is never lowered
-- by any code path — not by the reset, not by the delete endpoints.
-- Both are folded by the SAME upsert, so there is no second writer to
-- drift out of step.
--
-- The backfill takes the current value only. Anyone whose best was
-- already reset before this migration stays lost — their historic high
-- lives on in `client_difficulty_statistics_entity`, but that table is
-- pruned at 14 days, so a general backfill from it would restore an
-- arbitrary subset. Restoring a specific miner is a one-row UPDATE and
-- an operator decision, not something a migration should guess at.
ALTER TABLE address_settings_entity
  ADD COLUMN IF NOT EXISTS "allTimeBestDifficulty" double precision NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS "allTimeBestDifficultyUserAgent" character varying,
  ADD COLUMN IF NOT EXISTS "allTimeBestDifficultyAt" bigint;

UPDATE address_settings_entity
   SET "allTimeBestDifficulty" = "bestDifficulty",
       "allTimeBestDifficultyUserAgent" = "bestDifficultyUserAgent",
       "allTimeBestDifficultyAt" = "updatedAt"
 WHERE "bestDifficulty" > "allTimeBestDifficulty";
