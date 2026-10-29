-- Per address key (the lowercased key an address token names), the moment
-- before which every token for that key is void. The UI sidecar pushes it
-- when a password changes, a Lightning link goes or an address is deleted.
--
-- A new table: a binary one release older neither reads nor writes it.

CREATE TABLE IF NOT EXISTS address_token_revocation (
  "addressKey" text PRIMARY KEY,
  "revokedBefore" bigint NOT NULL,
  "updatedAt" bigint NOT NULL
);
