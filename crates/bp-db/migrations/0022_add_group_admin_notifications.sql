-- Per-subscription switch for the notice a Team admin gets when someone asks
-- to join their Team, on every channel that can carry it: app push
-- (FCM / UnifiedPush), Telegram and ntfy. On by default, like the other
-- per-event switches a new subscription starts with.
--
-- NOT NULL with a constant default: catalog-only in PostgreSQL, and a binary
-- one release older neither reads nor writes the column.

ALTER TABLE push_subscription_entity
  ADD COLUMN IF NOT EXISTS "groupAdminNotificationsEnabled" boolean NOT NULL DEFAULT true;
ALTER TABLE telegram_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "groupAdminNotificationsEnabled" boolean NOT NULL DEFAULT true;
ALTER TABLE ntfy_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "groupAdminNotificationsEnabled" boolean NOT NULL DEFAULT true;
