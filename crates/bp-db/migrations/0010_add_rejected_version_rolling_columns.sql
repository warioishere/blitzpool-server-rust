-- A fourth rejected-share column pair on `client_statistics_entity`, for
-- shares rejected because the miner changed block-header version bits
-- outside the mask it negotiated.
--
-- BIP-310 defines that rejection on the `version-rolling.mask` return
-- value: "Bits set to 1 are allowed to be changed by the miner. If a miner
-- changes bits with mask value 0, the server will reject the submit." The
-- pool did not enforce it until now, so the reason had nowhere to go.
--
-- Its own pair rather than folded into `rejectedLowDifficultyShare*`: the
-- proof-of-work of such a share may be perfectly good. A difficulty miss is
-- normal churn and needs no action; this one means a miner is ignoring what
-- it negotiated, and an operator who cannot tell them apart cannot act on
-- either.
--
-- ⚠️ `Stale` is still folded into `rejectedJobNotFound*` in
-- `bp_share_stats_sink::hooks`, for the same "there is no column for it"
-- reason this migration removes for version rolling. That fold predates
-- this table having room and is deliberate debt, not a design: the
-- pool-wide `pool_rejected_statistics_entity` already keeps Stale as its
-- own row, so the per-session counters are the only place the two are
-- indistinguishable. Give Stale its own pair the same way.
ALTER TABLE client_statistics_entity
  ADD COLUMN IF NOT EXISTS "rejectedVersionRollingCount" INTEGER DEFAULT 0 NOT NULL,
  ADD COLUMN IF NOT EXISTS "rejectedVersionRollingDiff1" REAL DEFAULT '0'::real NOT NULL;
