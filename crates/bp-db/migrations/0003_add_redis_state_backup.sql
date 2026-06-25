-- Periodic best-effort backup of the live PPLNS + Group-Solo Redis state
-- (the sliding-window / round per-address share weights) so an operator can
-- MANUALLY reconstruct it after a Redis wipe/corruption/bad deploy. Each
-- backup run writes one row per Redis key (verbatim DUMP payload) sharing a
-- single captured_at. Restore is operator-triggered
-- (`blitzpool --restore-redis-state`), never automatic — there is no
-- fail-state detection.
--
-- Rust-only table (the TS pool has no equivalent), so it always materialises
-- here. Idempotent (IF NOT EXISTS). See bin/blitzpool/src/redis_backup.rs.
CREATE TABLE IF NOT EXISTS redis_state_backup (
    id          bigserial PRIMARY KEY,
    captured_at bigint    NOT NULL,   -- epoch ms, one shared value per backup run
    scope       text      NOT NULL,   -- 'pplns' | 'groupsolo'
    redis_key   text      NOT NULL,
    dump        bytea     NOT NULL     -- Redis DUMP payload (RESTORE-able verbatim)
);

-- Restore reads the newest captured_at; pruning deletes the oldest. Both want
-- captured_at ordered.
CREATE INDEX IF NOT EXISTS redis_state_backup_captured_at_idx
    ON redis_state_backup (captured_at DESC);
