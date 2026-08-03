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
-- 312 500 000 sats.
--
--     ppm = round(finderBonusSats * 1000000 / 312500000)
--
-- THIS IS A LOWER BOUND, not an exact preservation, and the gap is the
-- pool fee. The new bonus is a fraction of the MINER CUT — the finder
-- takes `f · (1 − fee) · T` off the top — whereas the divisor above is
-- the whole subsidy. Preserving the old satoshi amount exactly would
-- need `f = B / ((1 − fee) · T)`, so every converted value comes out
-- short by exactly the fee fraction:
--
--     exact_ppm = ppm / (1 - fee)      e.g. +1.5 % at a 1.5 % pool fee
--
-- The migration cannot close that gap on its own: the fee is engine
-- configuration (`GroupSoloEngineConfig::fee_percent`), not a column,
-- so there is nothing here to read it from. Hardcoding one operator's
-- fee would be worse than a documented bias. An operator who wants the
-- old amount preserved to the satoshi applies the correction above by
-- hand, or simply sets the percentage they actually want — which is now
-- what the admin UI shows.
--
-- Block fees are deliberately ignored: they push the other way and vary
-- per block, which is exactly what a proportion is supposed to track.
--
-- `finderBonusSats` is KEPT (unread by the code from here on) so the
-- conversion stays auditable and nothing is destroyed. Drop it in a
-- later release once every group's percentage has been eyeballed.
ALTER TABLE pplns_group
  ADD COLUMN IF NOT EXISTS "finderBonusPpm" INTEGER;

-- The cast sits OUTSIDE `LEAST`, so the clamp happens first and the
-- integer conversion can never see an out-of-range value. Casting
-- inside would evaluate before the clamp, and a legacy row big enough
-- to overflow int4 after scaling (`finderBonusSats` is a plain bigint
-- with no CHECK) would abort the migration — i.e. fail the pool's boot
-- — with an "integer out of range" that names no group.
UPDATE pplns_group
   SET "finderBonusPpm" = LEAST(
         500000,  -- MAX_FINDER_BONUS_PPM
         ROUND("finderBonusSats"::numeric * 1000000 / 312500000)
       )::integer
 WHERE "finderBonusSats" IS NOT NULL
   AND "finderBonusSats" > 0
   AND "finderBonusPpm" IS NULL;
