-- The forum topic (Telegram `message_thread_id`) a subscription was made in,
-- so its notices go to that topic. NULL is the chat's main topic, and a chat
-- without topics.
--
-- Nullable without a default: catalog-only in PostgreSQL, and a binary one
-- release older neither reads nor writes the column.

ALTER TABLE telegram_subscriptions_entity
  ADD COLUMN IF NOT EXISTS "messageThreadId" bigint;
