-- Two statistics tables and two indexes that nothing reads or writes.
--
-- client_difficulty_statistics_entity and client_rejected_statistics_entity
-- duplicate columns of client_statistics_entity ("maxDifficulty" and the
-- per-reason reject counts), which is what every reader uses.
--
-- IDX_cs_real_time_cov is partial on "sessionId" <> 'AGG' AND address <>
-- 'POOL'. No query carries that predicate, so the planner can never pick it.
-- IDX_as_bestdifficulty_desc orders address_settings by "bestDifficulty"
-- across addresses, which no query asks for.
--
-- A plain DROP INDEX holds an exclusive lock on its table for the moment of
-- the drop; DROP INDEX CONCURRENTLY cannot run inside a migration's
-- transaction.

DROP TABLE IF EXISTS client_difficulty_statistics_entity;
DROP TABLE IF EXISTS client_rejected_statistics_entity;
DROP INDEX IF EXISTS "IDX_cs_real_time_cov";
DROP INDEX IF EXISTS "IDX_as_bestdifficulty_desc";
