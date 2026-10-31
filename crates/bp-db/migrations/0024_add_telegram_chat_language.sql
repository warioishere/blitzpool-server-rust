-- The reply language a Telegram chat picked, so it survives a restart. Kept
-- per chat, not per subscription: a chat picks its language before it
-- follows any address.
--
-- A new table: a binary one release older neither reads nor writes it.

CREATE TABLE IF NOT EXISTS telegram_chat_language (
  "telegramChatId" bigint PRIMARY KEY,
  language text NOT NULL,
  "updatedAt" bigint NOT NULL
);
