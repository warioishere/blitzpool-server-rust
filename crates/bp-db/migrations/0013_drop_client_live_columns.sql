-- The live per-session fields moved out of Postgres into the
-- `client:live:*` Redis hashes (one hash per session, TTL on the
-- dead-session-sweep clock). `client_entity` keeps only the birth row:
-- PK (address, clientName, sessionId), userAgent, startTime, firstSeen,
-- createdAt, updatedAt (stamped at birth/re-register/soft-delete only),
-- deletedAt.
--
-- These four columns were rewritten ~3×/minute per active session and
-- were the load behind the payout slow-statement bursts; their two bulk
-- writers (`bulk_touch_clients_for_share`, `bulk_set_client_hashrate`)
-- and the boot-time hashRate reset are deleted in the same change.
--
-- CLIENT_ENTITY_BULK_WRITE_LOCK is NOT deleted — an earlier version of
-- this comment said it was. It still guards `bulk_upsert_clients`, and
-- any future multi-row writer of `client_entity` must still take it.
-- What changes is what it serialises: no longer two 30 s/60 s statements
-- over the same ~700 rows, but ~9 row births per minute against a
-- once-per-minute sweep that usually touches nothing.
--
-- All-time best difficulty is unaffected — it lives in
-- address_settings_entity.
ALTER TABLE client_entity DROP COLUMN IF EXISTS "hashRate";
ALTER TABLE client_entity DROP COLUMN IF EXISTS "currentDifficulty";
ALTER TABLE client_entity DROP COLUMN IF EXISTS "channelCount";
ALTER TABLE client_entity DROP COLUMN IF EXISTS "bestDifficulty";
