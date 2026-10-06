-- The pool workers chart counts distinct addresses and workers per slot over
-- the last week, about 880 000 rows. On the plain ("time") index Postgres
-- fetches every row from the table and sorts each slot by address; with
-- ("time", address, "clientName") it answers from the index alone, already
-- in that order.
--
-- Measured on a prod-sized copy (1.76 M rows, 1008 slots in range):
-- 1.6 to 2.1 s on ("time"), 0.34 s on the new index, which is 130 MB
-- against 12 MB. The new index leads with "time", so it also serves the
-- retention DELETE; that measured 2.5 ms on ("time") and 5 to 8 ms on the
-- new one, so the plain index goes.
--
-- A plain CREATE INDEX blocks writes to the table while it builds (1.7 s on
-- the copy); reads go on. CREATE INDEX CONCURRENTLY cannot run inside a
-- migration's transaction.
CREATE INDEX IF NOT EXISTS "IDX_cs_time_address_client"
    ON client_statistics_entity ("time", address, "clientName");
DROP INDEX IF EXISTS "IDX_7d081302c6f984f26f81caa5cc";
