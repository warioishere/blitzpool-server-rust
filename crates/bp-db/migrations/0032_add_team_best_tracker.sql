-- The Team best the notify cron last announced or recorded, one row per
-- Team that has followers, so a best that rose while notify was down is
-- announced when it comes back instead of being taken as the first sight.
--
-- A new table: a binary one release older never touches it.

CREATE TABLE IF NOT EXISTS team_best_tracker (
  "groupId" uuid PRIMARY KEY,
  "bestDifficulty" double precision NOT NULL,
  "updatedAt" bigint NOT NULL
);
