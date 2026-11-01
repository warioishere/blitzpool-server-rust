-- Whether a Telegram subscription was made in a group chat. A group sees
-- notices without the followed address or what it was paid.
--
-- NOT NULL with a constant default: catalog-only in PostgreSQL, and a binary
-- one release older neither reads nor writes the column.

ALTER TABLE telegram_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "groupChat" boolean NOT NULL DEFAULT false;
