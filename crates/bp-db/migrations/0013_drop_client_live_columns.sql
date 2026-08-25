-- The live per-session fields moved out of Postgres into the
-- `client:live:*` Redis hashes (one hash per session, TTL on the
-- dead-session-sweep clock). `client_entity` keeps only the birth row:
-- PK (address, clientName, sessionId), userAgent, startTime, firstSeen,
-- createdAt, updatedAt (stamped at birth/re-register/soft-delete only),
-- deletedAt.
--
-- These four columns were rewritten ~3×/minute per active session and
-- were the load behind the payout slow-statement bursts; their writers,
-- the CLIENT_ENTITY_BULK_WRITE_LOCK advisory lock, and the boot-time
-- hashRate reset are deleted in the same change. All-time best
-- difficulty is unaffected — it lives in address_settings_entity.
ALTER TABLE client_entity DROP COLUMN IF EXISTS "hashRate";
ALTER TABLE client_entity DROP COLUMN IF EXISTS "currentDifficulty";
ALTER TABLE client_entity DROP COLUMN IF EXISTS "channelCount";
ALTER TABLE client_entity DROP COLUMN IF EXISTS "bestDifficulty";
