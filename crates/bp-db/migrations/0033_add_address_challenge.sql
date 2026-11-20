-- The pending signed challenge of every address proof: one row per address
-- and purpose (`ownership` for the ownership proof, `extranonce` for the
-- extranonce token request). A new request for the same purpose replaces
-- the row.
--
-- The unexpired rows of `pplns_ownership_challenge` and
-- `pplns_extranonce_challenge` are copied, so a challenge issued just before
-- the deploy can still be redeemed. Both tables stay: a binary one release
-- older reads and writes them, so it starts and runs against this schema.

CREATE TABLE IF NOT EXISTS address_challenge (
  address character varying(62) NOT NULL,
  purpose character varying(16) NOT NULL
    CONSTRAINT address_challenge_purpose CHECK (purpose IN ('ownership', 'extranonce')),
  message text NOT NULL,
  "createdAt" bigint NOT NULL,
  "expiresAt" bigint NOT NULL,
  CONSTRAINT address_challenge_pkey PRIMARY KEY (address, purpose)
);

INSERT INTO address_challenge (address, purpose, message, "createdAt", "expiresAt")
SELECT address, 'ownership', message, "createdAt", "expiresAt"
FROM pplns_ownership_challenge
WHERE "expiresAt" > (EXTRACT(EPOCH FROM now()) * 1000)::bigint
ON CONFLICT (address, purpose) DO NOTHING;

INSERT INTO address_challenge (address, purpose, message, "createdAt", "expiresAt")
SELECT address, 'extranonce', message, "createdAt", "expiresAt"
FROM pplns_extranonce_challenge
WHERE "expiresAt" > (EXTRACT(EPOCH FROM now()) * 1000)::bigint
ON CONFLICT (address, purpose) DO NOTHING;
