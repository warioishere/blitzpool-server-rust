-- Finder bonus as a PROPORTION of the miner cut, in parts-per-million
-- (1 % = 10 000 ppm), replacing the fixed-satoshi `finderBonusSats`.
--
-- Why: SV2 ext 0x0003 §4 pays every output `weight · T / W`, so a weight
-- IS a fraction of the block. A fixed satoshi amount has to be projected
-- against one chosen revenue to become a weight — and then any party
-- paying at a DIFFERENT revenue delivers a different bonus. A
-- job-declaring client builds its coinbase from its own template, so it
-- did exactly that: measured at 25 % above the reference revenue the
-- finder was overpaid by a quarter of the bonus, and only a signed
-- ledger carrying the difference into the next block could correct it.
-- A proportion is exact at every revenue, for every payer, and leaves
-- nothing to correct.
--
-- Conversion: against the current epoch's block subsidy, 3.125 BTC =
-- 312 500 000 sats. Pool fee and block fees are deliberately left out —
-- they move the result by well under one percent of the bonus, and a
-- fixed divisor documented here is one an operator can re-check by hand.
--
--     ppm = round(finderBonusSats * 1000000 / 312500000)
--
-- `finderBonusSats` is KEPT (unread by the code from here on) so the
-- conversion stays auditable and nothing is destroyed. Drop it in a
-- later release once every group's percentage has been eyeballed.
ALTER TABLE pplns_group
  ADD COLUMN IF NOT EXISTS "finderBonusPpm" INTEGER;

UPDATE pplns_group
   SET "finderBonusPpm" = LEAST(
         500000,  -- MAX_FINDER_BONUS_PPM
         ROUND("finderBonusSats"::numeric * 1000000 / 312500000)::integer
       )
 WHERE "finderBonusSats" IS NOT NULL
   AND "finderBonusSats" > 0
   AND "finderBonusPpm" IS NULL;
