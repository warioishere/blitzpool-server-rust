-- Self-service join-link for Blockparty groups (mirrors group-solo's open invite):
-- the admin shares one link, members open it, prove their address (email OR
-- signature), and self-join. One active link per group (PK groupId), token
-- unique for lookup.
--
-- Idempotent (IF NOT EXISTS): a fresh DB from db/schema.sql already has it.
CREATE TABLE IF NOT EXISTS blockparty_join_link (
    "groupId" uuid NOT NULL,
    token character varying(64) NOT NULL,
    "expiresAt" bigint NOT NULL,
    "createdAt" bigint NOT NULL,
    CONSTRAINT blockparty_join_link_pkey PRIMARY KEY ("groupId"),
    CONSTRAINT blockparty_join_link_token_key UNIQUE (token)
);
