-- Customer-set extranonce prefix per worker (the custom-extranonce API).
--
-- One paying customer wants to pick his own extranonce-1 instead of taking the
-- pool-allocated one. Authorisation is a FRESH Bitcoin message signature per
-- change: an existing pplns_address_ownership row proves the address signed at
-- SOME point, which is not an auth check (anyone could then post for that
-- address), so each change carries its own signed challenge.
--
--   pplns_extranonce_challenge — the short-lived message the address must sign.
--                                The requested change is stored ALONGSIDE the
--                                message so verify can check that the signature
--                                covers this exact (worker, prefix) and not
--                                some other one. PK address: one pending
--                                change per address at a time, mirroring
--                                pplns_ownership_challenge.
--   pplns_custom_extranonce    — the applied override, read at channel-open.
--
-- `prefix` is the 4-byte extranonce prefix as an unsigned 32-bit value. Stored
-- as bigint because Postgres has no unsigned integer type; the CHECK pins the
-- u32 range so the Rust side can narrow bigint -> u32 without a fallible
-- conversion at every read.
--
-- UNIQUE (address, prefix) — deliberately scoped to ONE address, not global.
-- Prefix uniqueness only matters between connections that hash the SAME
-- coinbase (same bp_mining_job cache key = same payouts + template; see
-- bp_common::extranonce). The pool is non-custodial, so:
--   * same address, two workers, same prefix -> Solo pays the same address ->
--     identical coinbase -> the prefix is the sole work-partitioner -> the two
--     workers really would grind the same search space. Rejected here.
--   * different addresses, same prefix -> different payout outputs ->
--     different coinbase -> different header regardless of the prefix ->
--     harmless. Allowed; a global UNIQUE would reject it for no reason.
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has these tables, so this migration is a no-op there.
CREATE TABLE IF NOT EXISTS pplns_extranonce_challenge (
    address character varying(62) NOT NULL,
    worker character varying NOT NULL,
    prefix bigint NOT NULL,
    message text NOT NULL,
    "createdAt" bigint NOT NULL,
    "expiresAt" bigint NOT NULL,
    CONSTRAINT pplns_extranonce_challenge_pkey PRIMARY KEY (address),
    CONSTRAINT pplns_extranonce_challenge_prefix_u32 CHECK (prefix >= 0 AND prefix <= 4294967295)
);

CREATE TABLE IF NOT EXISTS pplns_custom_extranonce (
    address character varying(62) NOT NULL,
    worker character varying NOT NULL,
    prefix bigint NOT NULL,
    "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    CONSTRAINT pplns_custom_extranonce_pkey PRIMARY KEY (address, worker),
    CONSTRAINT pplns_custom_extranonce_address_prefix_key UNIQUE (address, prefix),
    CONSTRAINT pplns_custom_extranonce_prefix_u32 CHECK (prefix >= 0 AND prefix <= 4294967295)
);

CREATE INDEX IF NOT EXISTS "IDX_pplns_extranonce_challenge_expiresAt"
    ON pplns_extranonce_challenge USING btree ("expiresAt");
