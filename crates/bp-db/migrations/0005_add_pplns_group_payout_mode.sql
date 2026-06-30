-- Per-group payout mode for Group-Solo: 'prop' (classic per-round PROP, the
-- legacy behavior) or 'window' (a continuously-sliding time window, like a
-- time-based PPLNS). Chosen once at group creation and immutable thereafter.
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has the column, so this is a no-op there. DEFAULT 'prop' backfills
-- every existing group as the classic PROP-per-round mode — no behavior change
-- for groups created before this migration.
ALTER TABLE pplns_group
    ADD COLUMN IF NOT EXISTS "payoutMode" character varying(16) NOT NULL DEFAULT 'prop';
