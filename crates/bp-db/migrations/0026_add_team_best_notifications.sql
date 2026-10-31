-- Team round best: a notice to a Team's members when the best share of the
-- Team's current round rises. The switch sits on each Telegram and ntfy
-- subscription, on by default like the other per-event switches; it fires
-- only for an address that is a member of a Team.
--
-- NOT NULL with a constant default: catalog-only in PostgreSQL, and a binary
-- one release older neither reads nor writes the column.

ALTER TABLE telegram_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "teamBestNotificationsEnabled" boolean NOT NULL DEFAULT true;

ALTER TABLE ntfy_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "teamBestNotificationsEnabled" boolean NOT NULL DEFAULT true;

