-- BTC address-ownership proof via message signature. A generic "this address
-- proved control of its key" primitive, verified by a Bitcoin message signature
-- (BIP-322 / BIP-137 / Electrum). Two consumers:
--   1. group-invite eligibility — a 2nd equivalent option next to the verified
--      email (pplns_address_email), so a miner can be invited without an email.
--   2. (later) the custom-extranonce override auth gate.
--
--   pplns_ownership_challenge — the short-lived exact message the address must
--                               sign (PK address; only the most recent is valid).
--   pplns_address_ownership   — the verified binding (PK address).
--
-- Idempotent (IF NOT EXISTS): a fresh DB bootstrapped from db/schema.sql already
-- has these tables, so this migration is a no-op there.
CREATE TABLE IF NOT EXISTS pplns_ownership_challenge (
    address character varying(62) NOT NULL,
    message text NOT NULL,
    "createdAt" bigint NOT NULL,
    "expiresAt" bigint NOT NULL,
    CONSTRAINT pplns_ownership_challenge_pkey PRIMARY KEY (address)
);

CREATE TABLE IF NOT EXISTS pplns_address_ownership (
    address character varying(62) NOT NULL,
    -- which signature family verified: 'bip322' | 'bip137' | 'electrum'
    method character varying(16) NOT NULL,
    -- resolved script type: 'p2pkh' | 'p2sh-p2wpkh' | 'p2wpkh' | 'p2tr'
    "scriptType" character varying(16) NOT NULL,
    "verifiedAt" bigint NOT NULL,
    "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
    CONSTRAINT pplns_address_ownership_pkey PRIMARY KEY (address)
);

CREATE INDEX IF NOT EXISTS "IDX_pplns_ownership_challenge_expiresAt"
    ON pplns_ownership_challenge USING btree ("expiresAt");
