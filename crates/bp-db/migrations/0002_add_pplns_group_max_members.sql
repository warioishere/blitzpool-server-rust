-- Per-group hard member cap. NULL = no limit (default / existing behaviour).
-- Enforced server-side at the single add-member chokepoint, so every join
-- path (directed invite, open invite link, approved join request) is rejected
-- once the cap is reached.
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has the column, so this is a no-op there. On the shared production
-- DB the TS pool's own migration adds the column first, so this is a no-op
-- there too — it only materialises the column on a Rust-managed DB missing it.
ALTER TABLE pplns_group
    ADD COLUMN IF NOT EXISTS "maxMembers" int;
