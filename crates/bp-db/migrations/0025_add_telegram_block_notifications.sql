-- Per-subscription switch for block notices on Telegram, which app push
-- already has (`push_subscription_entity."blockNotificationsEnabled"`). On by
-- default, like the other per-event switches a new subscription starts with.
--
-- NOT NULL with a constant default: catalog-only in PostgreSQL, and a binary
-- one release older neither reads nor writes the column.

ALTER TABLE telegram_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "blockNotificationsEnabled" boolean NOT NULL DEFAULT true;
