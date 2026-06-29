-- Number of mining channels open on a session's downstream connection.
-- 1 for a direct miner (one device → one channel); > 1 when a rental proxy
-- bundles several same-rig devices onto a single connection. Persisted so the
-- API (a separate process from the stratum core) can flag a bundled session's
-- difficulty as aggregated in the UI.
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has the column, so this is a no-op there. DEFAULT 1 backfills every
-- existing row as a single-channel (non-aggregated) session.
ALTER TABLE client_entity
    ADD COLUMN IF NOT EXISTS "channelCount" integer NOT NULL DEFAULT 1;
