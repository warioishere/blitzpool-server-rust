-- Customer-set extranonce prefix per worker (the custom-extranonce API).
--
-- One paying customer wants to pick his own extranonce-1 per worker instead of
-- taking the pool-allocated one. Auth is a stored bearer TOKEN: the address
-- proves key control once by signing a challenge, the API issues a token
-- (random, only its hash stored — the `adminTokenHash` pattern), and every
-- headless "set the EN for this worker" call carries that token. The feature is
-- Solo-only and cannot move money (the coinbase still pays the address), so a
-- long-lived token is an acceptable, low-stakes credential.
--
--   pplns_extranonce_challenge — the short-lived message an address signs to be
--                                issued a token (PK address; nonced + expiring
--                                so the signature itself is one-time and never
--                                becomes a reusable credential).
--   pplns_extranonce_token     — the issued token's hash (PK address). Re-issue
--                                overwrites it, revoking the previous token.
--   pplns_custom_extranonce    — the applied override, read at channel-open.
--
-- `prefix` is the 4-byte extranonce prefix as an unsigned 32-bit value. Stored
-- as bigint because Postgres has no unsigned integer type; the CHECK pins the
-- u32 range so the Rust side can narrow bigint -> u32 without a fallible
-- conversion at every read.
--
-- UNIQUE (address, prefix) on the overrides — deliberately scoped to ONE
-- address, not global. Prefix uniqueness only matters between connections that
-- hash the SAME coinbase (same payouts + template; see bp_common::extranonce).
-- The pool is non-custodial, so:
--   * same address, two workers, same prefix -> Solo pays the same address ->
--     identical coinbase -> the prefix is the sole work-partitioner -> the two
--     workers would grind the same search space. Rejected here.
--   * different addresses, same prefix -> different payout outputs ->
--     different coinbase -> different header regardless of the prefix ->
--     harmless. Allowed; a global UNIQUE would reject it for no reason.
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql
-- already has these tables, so this migration is a no-op there.
CREATE TABLE IF NOT EXISTS pplns_extranonce_challenge (
    address character varying(62) NOT NULL,
    message text NOT NULL,
    "createdAt" bigint NOT NULL,
    "expiresAt" bigint NOT NULL,
    CONSTRAINT pplns_extranonce_challenge_pkey PRIMARY KEY (address)
);

CREATE TABLE IF NOT EXISTS pplns_extranonce_token (
    address character varying(62) NOT NULL,
    "tokenHash" character varying(64) NOT NULL,
    "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    CONSTRAINT pplns_extranonce_token_pkey PRIMARY KEY (address)
);

CREATE TABLE IF NOT EXISTS pplns_custom_extranonce (
    address character varying(62) NOT NULL,
    worker character varying NOT NULL,
    prefix bigint NOT NULL,
    "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    CONSTRAINT pplns_custom_extranonce_pkey PRIMARY KEY (address, worker),
    -- DEFERRABLE so a batch update can SWAP prefixes between two of the
    -- address's own workers inside one transaction. Postgres checks a plain
    -- UNIQUE per statement, so `rig1 := rig2's prefix` would collide with
    -- rig2's still-old row and abort the batch. Deferred, the check runs at
    -- COMMIT: transient in-transaction duplicates are fine, a genuine
    -- duplicate (two workers left on the same prefix) still fails. Stays
    -- INITIALLY IMMEDIATE so single-row writes behave exactly as before —
    -- only the batch path opts in via `SET CONSTRAINTS ... DEFERRED`.
    CONSTRAINT pplns_custom_extranonce_address_prefix_key
        UNIQUE (address, prefix) DEFERRABLE INITIALLY IMMEDIATE,
    CONSTRAINT pplns_custom_extranonce_prefix_u32 CHECK (prefix >= 0 AND prefix <= 4294967295)
);

CREATE INDEX IF NOT EXISTS "IDX_pplns_extranonce_challenge_expiresAt"
    ON pplns_extranonce_challenge USING btree ("expiresAt");
