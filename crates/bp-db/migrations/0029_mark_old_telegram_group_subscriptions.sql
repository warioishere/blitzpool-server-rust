-- A Telegram subscription in a group chat (negative chat id) whose row is not
-- marked as one gets the private notices: best difficulty, devices, hourly
-- stats and workers, join requests. Mark it and switch those off, exactly as
-- subscribing in a group does (`make_telegram_group_subscription`).
--
-- Data only: a binary one release older ignores "groupChat" and finds the
-- private switches off.

UPDATE telegram_subscriptions_entity
SET "bestDiffNotificationsEnabled" = false,
    "deviceNotificationsEnabled" = false,
    "hourlyStatsEnabled" = false,
    "hourlyWorkersEnabled" = false,
    "groupAdminNotificationsEnabled" = false,
    "groupChat" = true,
    "updatedAt" = (extract(epoch FROM now()) * 1000)::bigint
WHERE "telegramChatId" < 0
  AND NOT "groupChat"
  AND "deletedAt" IS NULL;
